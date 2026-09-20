# -*- coding: utf-8 -*-
"""媒体附件导出：图片(.dat) / 语音(silk) / 视频 / 文件。

图片（`msg/attach/<md5(会话)>/<年月>/Img/*.dat`）在微信 4.x 里是加密的：

    V1  头 `07 08 56 31 08 07`，AES-128-ECB，密钥固定 = md5("0")[:16]
    V2  头 `07 08 56 32 08 07`，AES-128-ECB，密钥每次随机，只在内存里短暂存在
    旧  单字节 XOR

结构：`[6B 头][4B aes_size LE][4B xor_size LE][1B 异或键][AES 密文][明文段][XOR 段]`

**关于 V2**：密钥不是常驻内存的，只在微信渲染该图片时临时生成。因此本工具
默认**不**尝试自动破解 V2，而是把图片按消息索引原样导出（`--copy-dat`），
并写出 `images.txt` 对照表。V1 会自动解密。想尝试自动找 V2 密钥可以用
`find_dat_aes_key()`（需要先在微信里点开过该图片，且较慢）。

语音（SILK）、视频（mp4）、文件（docx/xlsx/pdf…）都不加密，直接导出。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import re
import shutil
import struct
from dataclasses import dataclass, field

from Cryptodome.Cipher import AES

SIG_V1 = bytes.fromhex("070856310807")
SIG_V2 = bytes.fromhex("070856320807")
V1_KEY = hashlib.md5(b"0").hexdigest()[:16].encode()

IMG_EXT = ((b"\xff\xd8\xff", ".jpg"), (b"\x89PNG", ".png"), (b"GIF8", ".gif"),
           (b"RIFF", ".webp"), (b"BM", ".bmp"), (b"wxgf", ".wxgf"))

kernel32 = ctypes.windll.kernel32
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}


class _MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_p1", wt.DWORD),
                ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_p2", wt.DWORD)]


# ---------------------------------------------------------------------------
# dat 解码
# ---------------------------------------------------------------------------
def sniff_ext(data: bytes) -> str:
    for magic, ext in IMG_EXT:
        if data.startswith(magic):
            return ext
    return ".bin"


def _pkcs7_strip(data: bytes) -> bytes:
    if data and 1 <= data[-1] <= 16 and data[-data[-1]:] == bytes([data[-1]]) * data[-1]:
        return data[:-data[-1]]
    return data


def dat_layout(data: bytes):
    """返回 (aes_ct, mid, xor_ct, xor_key_hint)；不符合结构返回 None。"""
    if len(data) < 15:
        return None
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    if aes_size <= 0 or aes_size > len(data):
        return None
    aligned = ((aes_size + 15) // 16) * 16
    start = 15
    end = start + aligned
    if end > len(data):
        return None
    xor_start = len(data) - xor_size if xor_size else len(data)
    if xor_start < end:
        return None
    return data[start:end], data[end:xor_start], data[xor_start:], data[14]


def decode_dat(data: bytes, aes_key: bytes | None = None,
               xor_key: int | None = None) -> bytes | None:
    """解出一个 .dat；失败返回 None（V2 没密钥时会返回 None）。"""
    sig = data[:6]
    if sig == SIG_V1:
        key = V1_KEY
    elif sig == SIG_V2:
        key = aes_key
        if not key:
            return None
    else:
        for k in range(256):
            head = bytes(b ^ k for b in data[:4])
            if sniff_ext(head) != ".bin":
                return bytes(b ^ k for b in data)
        return None
    lay = dat_layout(data)
    if not lay:
        return None
    aes_ct, mid, xor_ct, hint = lay
    try:
        pt = _pkcs7_strip(AES.new(key, AES.MODE_ECB).decrypt(aes_ct))
    except ValueError:
        return None
    xk = xor_key if xor_key is not None else hint
    out = pt + mid + bytes(b ^ (xk & 0xFF) for b in xor_ct)
    i = out.find(b"\xff\xd9")
    if out.startswith(b"\xff\xd8") and i > 0:
        out = out[:i + 2]
    i = out.find(b"IEND")
    if out.startswith(b"\x89PNG") and i > 0:
        out = out[:i + 4]
    return out


# ---------------------------------------------------------------------------
# 可选：从内存里找 V2 密钥（慢，且需要该图片最近被渲染过）
# ---------------------------------------------------------------------------
def _regions(h):
    out, addr, mbi = [], 0, _MBI()
    while addr < 0x7FFF_FFFF_FFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == MEM_COMMIT and mbi.Protect in READABLE
                and 0 < mbi.RegionSize < 500 * 1024 * 1024):
            out.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out


def _read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[: n.value]
    return None


def find_dat_aes_key(sample_path: str, pids=None, progress=None):
    """用样本 .dat 在微信内存里搜索 V2 的 AES 密钥。

    判据：候选密钥必须是 16 字节可打印 ASCII，且用它解出的第一段密文，
    前缀要与其后紧跟的**明文段**一致。
    """
    progress = progress or (lambda m: None)
    with open(sample_path, "rb") as f:
        data = f.read()
    if data[:6] != SIG_V2:
        progress("样本不是 V2 格式")
        return None
    lay = dat_layout(data)
    if not lay:
        return None
    aes_ct, mid, _xor, _hint = lay
    if len(mid) < 16:
        progress("样本没有内嵌明文段，无法校验候选密钥（试试 _t.dat）")
        return None
    expect = mid[:16]

    if pids is None:
        from .key import find_weixin_processes
        pids = [p["pid"] for p in find_weixin_processes()]
    for pid in pids:
        h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        try:
            for base, size in _regions(h):
                buf = _read(h, base, size)
                if not buf or len(buf) < 64:
                    continue
                # 只按 16 字节对齐滑动，并先做可打印判断，避免大量无效 AES
                for i in range(0, len(buf) - 16 + 1, 16):
                    cand = buf[i:i + 16]
                    if not all(0x20 <= b < 0x7F for b in cand):
                        continue
                    try:
                        out = AES.new(cand, AES.MODE_ECB).decrypt(aes_ct[:16])
                    except ValueError:
                        continue
                    if out[:len(expect)] == expect:
                        progress("找到图片密钥 %r (PID=%d @0x%X)" % (cand, pid, base + i))
                        return cand
        finally:
            kernel32.CloseHandle(h)
    progress("未在内存中找到图片 AES 密钥")
    return None


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------
@dataclass
class MediaStats:
    images: int = 0
    images_raw: int = 0
    voices: int = 0
    videos: int = 0
    files: int = 0
    extras: list = field(default_factory=list)


def export_voice(data, msgs, out_dir: str, progress=None) -> int:
    """导出语音为 .silk（SILK 格式，可用 silk-v3-decoder 转 mp3）。"""
    progress = progress or (lambda m: None)
    n = 0
    os.makedirs(out_dir, exist_ok=True)
    for m in msgs:
        if m["type"] != 34 or not m["server_id"]:
            continue
        blob = data.voice_blob(m["session"], m["server_id"])
        if not blob:
            continue
        stamp = m["time_str"].replace(":", "").replace("-", "").replace(" ", "_")
        path = os.path.join(out_dir, "voice_%s_%s.silk" % (stamp, m["server_id"]))
        with open(path, "wb") as f:
            f.write(blob)
        m["extra"]["voice_file"] = path
        n += 1
    if n:
        progress("语音 %d 条 -> %s" % (n, out_dir))
    return n


def _session_attach_index(attach_dir: str) -> dict:
    idx = {}
    if not attach_dir or not os.path.isdir(attach_dir):
        return idx
    for root, _dirs, files in os.walk(attach_dir):
        for f in files:
            if f.endswith(".dat"):
                idx.setdefault(os.path.splitext(f)[0], os.path.join(root, f))
    return idx


def export_images(data, session: str, msgs, out_dir: str,
                  aes_key: bytes | None = None, copy_dat: bool = True,
                  progress=None) -> int:
    """按消息里的 md5 把图片找出来；V1 自动解密，V2 视 copy_dat 决定是否原样复制。"""
    progress = progress or (lambda m: None)
    attach_dir = data.attach_dir(session)
    if not attach_dir:
        return 0
    index = _session_attach_index(attach_dir)
    if not index:
        return 0
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    for m in msgs:
        if m["type"] != 3:
            continue
        md5s = re.findall(r"\b[0-9a-f]{32}\b", m.get("content") or "")
        md5s += re.findall(r"\b[0-9a-f]{32}\b", m.get("packed_hex") or "")
        for md5 in dict.fromkeys(md5s):
            src = (index.get(md5) or index.get(md5 + "_h") or index.get(md5 + "_t"))
            if not src:
                continue
            with open(src, "rb") as f:
                raw = f.read()
            out = decode_dat(raw, aes_key, None)
            stamp = m["time_str"].replace(":", "").replace("-", "").replace(" ", "_")
            if out is not None:
                dst = os.path.join(out_dir, "img_%s_%s%s" % (stamp, md5[:8], sniff_ext(out)))
                with open(dst, "wb") as f:
                    f.write(out)
            elif copy_dat:
                dst = os.path.join(out_dir, "%s.dat" % md5)
                if not os.path.exists(dst):
                    shutil.copy2(src, dst)
            else:
                continue
            m["extra"].setdefault("images", []).append(dst)
            n += 1
            break
    if n:
        progress("图片 %d 张 -> %s" % (n, out_dir))
    return n


def copy_plain_media(data, out_dir: str, progress=None) -> tuple:
    """视频/文件在 msg/video、msg/file 下是明文，整体复制。"""
    progress = progress or (lambda m: None)
    nv = nf = 0
    for sub in ("video", "file"):
        base = os.path.join(data.msg_dir(), sub)
        if not os.path.isdir(base):
            continue
        dst_dir = os.path.join(out_dir, sub)
        for root, _dirs, files in os.walk(base):
            for f in files:
                src = os.path.join(root, f)
                dst = os.path.join(dst_dir, os.path.relpath(src, base))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    continue
                if sub == "video":
                    nv += 1
                else:
                    nf += 1
    if nv or nf:
        progress("视频 %d 个、文件 %d 个 -> %s" % (nv, nf, out_dir))
    return nv, nf


def export_session_media(data, session: str, msgs, out_root: str,
                         aes_key=None, copy_dat=True, progress=None) -> MediaStats:
    """导出某个会话的全部媒体，返回统计。"""
    progress = progress or (lambda m: None)
    os.makedirs(out_root, exist_ok=True)
    st = MediaStats()
    st.images = export_images(data, session, msgs, os.path.join(out_root, "image"),
                              aes_key=aes_key, copy_dat=copy_dat, progress=progress)
    st.voices = export_voice(data, msgs, os.path.join(out_root, "voice"), progress=progress)
    return st
