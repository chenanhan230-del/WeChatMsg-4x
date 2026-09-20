# -*- coding: utf-8 -*-
"""把微信 4.x 的加密数据库快照解密成普通 SQLite 文件。

要点：
  * 微信正在运行时会独占 `.db`，所以先复制快照（含 `-wal` / `-shm`）再解密。
  * 主库之后追加解密 `-wal` 里的增量页（SQLCipher 只加密 WAL 的数据页，
    帧头 24 字节是明文的），这样才拿得到最近的消息。
  * 解密完用 `PRAGMA quick_check` 抽检，失败自动重试（微信可能正在写页）。
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import struct
import tempfile
import time

from Cryptodome.Cipher import AES

from .common import (IV_SZ, PAGE_SZ, RESERVE_SZ, SALT_SZ, SQLITE_HDR,
                     verify_enc_key)

WAL_MAGIC = {0x377f0682, 0x377f0683}
WAL_HDR_SZ = 32
WAL_FRAME_HDR_SZ = 24


class DecryptError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# 单页 / 单库
# ---------------------------------------------------------------------------
def decrypt_page(enc_key: bytes, page: bytes, pgno: int) -> bytes:
    """解密一页。第 1 页去掉 16 字节 salt，其余页从 0 开始。"""
    if len(page) < PAGE_SZ:
        page = page + b"\x00" * (PAGE_SZ - len(page))
    iv = page[PAGE_SZ - RESERVE_SZ:PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        body = page[SALT_SZ:PAGE_SZ - RESERVE_SZ]
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(body)
        return SQLITE_HDR + dec + b"\x00" * RESERVE_SZ
    body = page[:PAGE_SZ - RESERVE_SZ]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(body)
    return dec + b"\x00" * RESERVE_SZ


def decrypt_file(src: str, dst: str, enc_key: bytes, apply_wal: bool = True) -> dict:
    """解密单个库；返回统计信息。"""
    size = os.path.getsize(src)
    total = (size + PAGE_SZ - 1) // PAGE_SZ
    with open(src, "rb") as f:
        page1 = f.read(PAGE_SZ)
    if len(page1) < PAGE_SZ:
        raise DecryptError("文件过小：%s" % src)
    if not verify_enc_key(enc_key, page1):
        raise DecryptError("密钥校验失败（HMAC 不匹配）：%s" % src)

    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        for pgno in range(1, total + 1):
            page = fi.read(PAGE_SZ)
            if not page:
                break
            fo.write(decrypt_page(enc_key, page, pgno))

    info = {"src": src, "dst": dst, "pages": total, "wal_frames": 0}
    if apply_wal:
        wal = src + "-wal"
        if os.path.exists(wal) and os.path.getsize(wal) > WAL_HDR_SZ:
            try:
                info["wal_frames"] = merge_wal(dst, wal, enc_key)
            except Exception as e:                      # noqa: BLE001
                info["wal_error"] = str(e)
    return info


def merge_wal(db_path: str, wal_path: str, enc_key: bytes) -> int:
    """把加密 WAL 里的增量页解密后写回已解密的库。

    WAL 布局：32 字节文件头（明文）+ N × [24 字节帧头(明文) + 4096 字节加密页]。
    只应用「帧里的 salt 与文件头当前 salt 相同」的帧，避免 checkpoint 后的
    旧世代帧把新页覆盖掉。
    """
    with open(wal_path, "rb") as f:
        wal = f.read()
    if len(wal) < WAL_HDR_SZ:
        return 0
    magic, ver, page_size = struct.unpack_from(">III", wal, 0)
    if magic not in WAL_MAGIC:
        return 0
    if page_size == 0:
        page_size = PAGE_SZ
    if page_size != PAGE_SZ:
        # 4.x 一律 4096，其它尺寸不处理以免写坏文件
        return 0
    salt1, salt2 = struct.unpack_from(">II", wal, 16)

    frames = []
    off = WAL_HDR_SZ
    while off + WAL_FRAME_HDR_SZ + PAGE_SZ <= len(wal):
        pgno, commit = struct.unpack_from(">II", wal, off)
        fs1, fs2 = struct.unpack_from(">II", wal, off + 8)
        page = wal[off + WAL_FRAME_HDR_SZ: off + WAL_FRAME_HDR_SZ + PAGE_SZ]
        off += WAL_FRAME_HDR_SZ + PAGE_SZ
        if pgno == 0:
            break
        if (fs1, fs2) != (salt1, salt2):     # 旧世代帧，跳过
            continue
        frames.append((pgno, page))
    if not frames:
        return 0

    applied = 0
    with open(db_path, "r+b") as f:
        for pgno, page in frames:
            f.seek((pgno - 1) * PAGE_SZ)
            f.write(decrypt_page(enc_key, page, pgno))
            applied += 1
    return applied


# ---------------------------------------------------------------------------
# 批量
# ---------------------------------------------------------------------------
def _snapshot(src: str, tmpdir: str, want_wal: bool = True) -> str:
    """复制一份库快照（含 -wal/-shm）到临时目录，返回新路径。"""
    dst = os.path.join(tmpdir, os.path.basename(src))
    shutil.copy2(src, dst)
    if want_wal:
        for suf in ("-wal", "-shm"):
            s = src + suf
            if os.path.exists(s):
                try:
                    shutil.copy2(s, dst + suf)
                except OSError:
                    pass
    return dst


def list_encrypted(db_storage: str) -> list[dict]:
    """列出待解密的库（供 UI/CLI 显示进度用）。"""
    out = []
    for root, _dirs, files in os.walk(db_storage):
        for f in files:
            if not f.endswith(".db"):
                continue
            p = os.path.join(root, f)
            try:
                if os.path.getsize(p) >= PAGE_SZ:
                    out.append({"rel": os.path.relpath(p, db_storage), "path": p})
            except OSError:
                continue
    return out


def quick_check(db_path: str) -> bool:
    """判断解密结果是否是一个可用的 SQLite 库。

    注意：FTS5 库（*_fts.db）里含虚拟表，`PRAGMA quick_check` 会直接报
    "SQL logic error"（缺 tokenizer 模块），这是**误报**而不是解密失败。
    这类库退化为「能读出 sqlite_master 即算通过」。
    """
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True)
    except sqlite3.Error:
        return False
    try:
        try:
            rows = con.execute("PRAGMA quick_check(1)").fetchall()
            return bool(rows) and rows[0][0] == "ok"
        except sqlite3.Error:
            try:
                con.execute("select count(*) from sqlite_master").fetchone()
                return True
            except sqlite3.Error:
                return False
    finally:
        con.close()


def decrypt_all(keys: dict[str, dict], db_storage: str, out_dir: str,
                progress=None, check_retries: int = 3) -> dict:
    """按 keys.json 的结构批量解密。

    keys: {相对路径: {"enc_key": hex, "salt": hex}}
    """
    progress = progress or (lambda m: None)
    results = {"ok": [], "failed": [], "skipped": []}
    os.makedirs(out_dir, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="wx4snap_")
    try:
        for i, (rel, info) in enumerate(sorted(keys.items()), 1):
            src = os.path.join(db_storage, rel)
            dst = os.path.join(out_dir, rel)
            if not os.path.exists(src):
                results["skipped"].append((rel, "源文件不存在"))
                progress("[%d/%d] 跳过 %s（源文件不存在）" % (i, len(keys), rel))
                continue
            enc_key = bytes.fromhex(info["enc_key"])
            last_err = None
            for attempt in range(1, check_retries + 1):
                try:
                    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
                    snap = _snapshot(src, tmpdir)
                    info2 = decrypt_file(snap, dst, enc_key)
                    if quick_check(dst):
                        results["ok"].append(rel)
                        progress("[%d/%d] %s  完成（%d 页, WAL %d 帧）"
                                 % (i, len(keys), rel, info2["pages"], info2["wal_frames"]))
                        last_err = None
                        break
                    last_err = "quick_check 未通过"
                except DecryptError as e:
                    last_err = str(e)
                    break
                except OSError as e:
                    last_err = "IO 错误：%s" % e
                if attempt < check_retries:
                    time.sleep(0.3)      # 微信可能在写页，等一拍再快照
            if last_err:
                results["failed"].append((rel, last_err))
                progress("[%d/%d] %s 失败：%s" % (i, len(keys), rel, last_err))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return results
