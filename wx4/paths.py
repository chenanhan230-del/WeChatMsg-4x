# -*- coding: utf-8 -*-
"""微信 4.x 安装路径 / 数据目录 / 账号目录 探测。

与 3.x 的区别：
    3.x:  HKCU\\Software\\Tencent\\WeChat  ->  FileSavePath
          <FileSavePath>\\WeChat Files\\<wxid>\\Msg\\*.db
    4.x:  %APPDATA%\\Tencent\\xwechat\\config\\*.ini  内容通常是 "MyDocument:" 表示
          “文档”文件夹，或者一个绝对路径
          <root>\\xwechat_files\\<wxid>_<4位hex>\\db_storage\\**
    其它:  HKCU\\Software\\Tencent\\Weixin 只有 InstallPath，不再有文件保存路径。
"""
from __future__ import annotations

import glob
import os
import re
import string
import winreg

XWECHAT_DIRNAME = "xwechat_files"
DB_STORAGE = "db_storage"
WXID_RE = re.compile(r"^(?P<wxid>.+?)_(?P<suffix>[0-9a-fA-F]{4})$")


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------
def _reg_value(root, path, name):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _documents_dir() -> str:
    """取“文档”文件夹真实路径（含 OneDrive 重定向/自定义位置的情况）。"""
    v = _reg_value(winreg.HKEY_CURRENT_USER,
                   r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                   "Personal")
    if v:
        expanded = os.path.expandvars(v)
        if os.path.isdir(expanded):
            return expanded
    # 回退：Shell Folders（已展开）
    v = _reg_value(winreg.HKEY_CURRENT_USER,
                   r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                   "Personal")
    if v and os.path.isdir(v):
        return v
    profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.join(profile, "Documents")


def get_install_path() -> str | None:
    """微信 4.x 安装目录（注册表 InstallPath）。"""
    p = _reg_value(winreg.HKEY_CURRENT_USER, r"Software\Tencent\Weixin", "InstallPath")
    if p and os.path.isdir(p):
        return p
    return None


def get_weixin_exe() -> str | None:
    """找到真正在运行的 Weixin.exe（安装目录下版本号子目录里的那个）。"""
    install = get_install_path()
    if install:
        # C:\Program Files\Tencent\Weixin\Weixin.exe 优先（快捷方式实际指向）
        direct = os.path.join(install, "Weixin.exe")
        if os.path.isfile(direct):
            return direct
        versions = []
        for name in os.listdir(install):
            sub = os.path.join(install, name)
            exe = os.path.join(sub, "Weixin.exe")
            if os.path.isfile(exe):
                versions.append((name, exe))
        if versions:
            versions.sort(key=lambda x: [int(p) if p.isdigit() else 0
                                         for p in re.split(r"[.\-]", x[0])], reverse=True)
            return versions[0][1]
    return None


# --------------------------------------------------------------------------
# 数据根目录
# --------------------------------------------------------------------------
def _roots_from_config() -> list[str]:
    """从 %APPDATA%\\Tencent\\xwechat\\config\\*.ini 推断 xwechat_files 根目录。"""
    out = []
    cfg_dir = os.path.join(os.environ.get("APPDATA", ""), "Tencent", "xwechat", "config")
    if not os.path.isdir(cfg_dir):
        return out
    for ini in glob.glob(os.path.join(cfg_dir, "*.ini")):
        raw = None
        for enc in ("utf-8", "gbk"):
            try:
                with open(ini, "r", encoding=enc) as f:
                    raw = f.read(1024).strip()
                break
            except (UnicodeDecodeError, OSError):
                continue
        if not raw:
            continue
        if raw.rstrip("\\/") == "MyDocument:":
            out.append(_documents_dir())
        elif os.path.isdir(raw):
            out.append(raw)
    return out


def _roots_from_registry() -> list[str]:
    out = []
    for hive_path, key in (
        (r"Software\Tencent\Weixin", "FileSavePath"),
        (r"Software\Tencent\WeChat", "FileSavePath"),
    ):
        v = _reg_value(winreg.HKEY_CURRENT_USER, hive_path, key)
        if not v:
            continue
        v = os.path.expandvars(v)
        if v.rstrip("\\/") == "MyDocument:":
            out.append(_documents_dir())
        elif os.path.isdir(v):
            out.append(v)
    return out


def _quick_scan_drives(max_depth: int = 3) -> list[str]:
    """兜底：在常见位置浅层搜索 xwechat_files。"""
    found = []
    candidates = []
    for drive in string.ascii_uppercase:
        root = f"{drive}:\\"
        if not os.path.isdir(root):
            continue
        candidates.append(root)
        for base in ("Users", "Documents", "WeChat", "Tencent", "ProgramData"):
            p = os.path.join(root, base)
            if os.path.isdir(p):
                candidates.append(p)
    seen = set()
    for base in candidates:
        if base in seen:
            continue
        seen.add(base)
        try:
            for entry in os.listdir(base):
                p = os.path.join(base, entry, XWECHAT_DIRNAME)
                if os.path.isdir(p):
                    found.append(os.path.join(base, entry))
                    continue
                p2 = os.path.join(base, XWECHAT_DIRNAME)
                if entry == XWECHAT_DIRNAME and os.path.isdir(p2):
                    found.append(base)
        except (PermissionError, OSError):
            continue
    return found


def get_xwechat_root() -> str | None:
    """定位 xwechat_files 目录本身。"""
    seen = set()
    for base in _roots_from_config() + _roots_from_registry() + [_documents_dir()]:
        base = os.path.normpath(base)
        if base in seen:
            continue
        seen.add(base)
        # base 本身可能就是 xwechat_files
        if os.path.basename(base) == XWECHAT_DIRNAME and os.path.isdir(base):
            return base
        p = os.path.join(base, XWECHAT_DIRNAME)
        if os.path.isdir(p):
            return p
    for base in _quick_scan_drives():
        base = os.path.normpath(base)
        if base in seen:
            continue
        seen.add(base)
        p = os.path.join(base, XWECHAT_DIRNAME)
        if os.path.isdir(p):
            return p
    return None


# --------------------------------------------------------------------------
# 账号目录
# --------------------------------------------------------------------------
def split_wxid(dirname: str) -> str | None:
    """从 `wxid_xxxxxxxxxxxx_dc5e` 里取出 wxid（去掉 4 位十六进制后缀）。

    4.x 的账号目录名 = wxid + '_' + 4 位十六进制后缀。但 wxid 本身可能以
    `_xxxx` 结尾（少见），因此只在后缀确实为 4 位十六进制时裁剪。
    """
    m = WXID_RE.match(dirname)
    if m:
        return m.group("wxid")
    return dirname


def list_account_dirs() -> list[dict]:
    """列出所有已登录过 / 有数据的账号目录。"""
    root = get_xwechat_root()
    if not root:
        return []
    out = []
    for name in sorted(os.listdir(root)):
        full = os.path.join(root, name)
        if not os.path.isdir(full) or name == "all_users":
            continue
        storage = os.path.join(full, DB_STORAGE)
        if not os.path.isdir(storage):
            continue
        try:
            mtime = max(
                (os.path.getmtime(os.path.join(r, f))
                 for r, _d, fs in os.walk(storage) for f in fs),
                default=0,
            )
        except OSError:
            mtime = 0
        out.append({
            "dir_name": name,
            "wxid": split_wxid(name),
            "path": full,
            "db_storage": storage,
            "mtime": mtime,
        })
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


def list_logged_in_wxids() -> list[str]:
    """从 all_users\\login\\<wxid>\\key_info.db 判断本机登录过哪些账号。"""
    root = get_xwechat_root()
    if not root:
        return []
    login = os.path.join(root, "all_users", "login")
    if not os.path.isdir(login):
        return []
    out = []
    for name in os.listdir(login):
        if os.path.isfile(os.path.join(login, name, "key_info.db")):
            out.append(name)
    return sorted(out)


def find_account(wxid: str | None = None) -> dict | None:
    """按 wxid 找账号目录，不指定时返回最近使用的那个。"""
    accounts = list_account_dirs()
    if not accounts:
        return None
    if not wxid:
        return accounts[0]
    for a in accounts:
        if a["wxid"] == wxid or a["dir_name"] == wxid:
            return a
    # 模糊匹配（前缀）
    for a in accounts:
        if a["wxid"].startswith(wxid) or wxid.startswith(a["wxid"]):
            return a
    return None


def describe() -> dict:
    """给 UI/CLI 用的一份环境报告。"""
    root = get_xwechat_root()
    return {
        "install_path": get_install_path(),
        "weixin_exe": get_weixin_exe(),
        "xwechat_root": root,
        "accounts": list_account_dirs(),
        "logged_in_wxids": list_logged_in_wxids(),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(describe(), ensure_ascii=False, indent=2))
