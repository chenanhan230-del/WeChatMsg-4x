# -*- coding: utf-8 -*-
"""发布前隐私扫描：找出不该进 GitHub 的产物与个人信息。"""
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 1) 按路径/文件名判断的“产物”
PATTERN_RULES = [
    (r"(^|/)wx4_keys?\.json$", "密钥文件（高危）"),
    (r"(^|/)all_keys\.json$", "密钥文件（高危）"),
    (r"\.db$", "SQLite 数据库"),
    (r"\.db-(wal|shm)$", "SQLite WAL/SHM"),
    (r"\.silk$", "语音文件"),
    (r"\.dat$", "微信图片 dat"),
    (r"(^|/)__pycache__(/|$)", "Python 缓存"),
    (r"\.pyc$", "Python 编译产物"),
    (r"\.log$", "日志"),
    (r"(^|/)\.idea(/|$)", "IDE 配置"),
    (r"(^|/)\.vscode(/|$)", "IDE 配置"),
    (r"(^|/)logs?(/|$)", "日志目录"),
    (r"(^|/)export(_test)?(/|$)", "导出产物"),
    (r"(^|/)decrypted(/|$)", "解密产物"),
    (r"(^|/)Msg(/|$)", "3.x 解密产物"),
    (r"(^|/)DataBase/(Msg|decrypted|export)(/|$)", "解密/导出产物"),
    (r"\.zip$|\.7z$|\.rar$", "压缩包"),
]

# 2) 内容里可能出现的个人隐私
CONTENT_RULES = [
    (re.compile(r"wxid_[0-9a-z]{6,}"), "出现 wxid"),
    (re.compile(r"\bwxid_[0-9a-z]{6,}_[0-9a-f]{4}\b"), "出现账号目录名"),
    (re.compile(r"C:\\\\?Users\\\\?[A-Za-z0-9_.\-]+"), "出现本机用户名路径"),
    (re.compile(r"/Users/[A-Za-z0-9_.\-]+/"), "出现本机用户名路径"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "疑似手机号"),
    (re.compile(r"[A-Za-z0-9._%+\-]+@(qq|163|126|gmail|outlook|foxmail)\.com", re.I),
     "疑似邮箱"),
]

TEXT_EXT = {".py", ".md", ".txt", ".json", ".ini", ".cfg", ".yml", ".yaml",
            ".html", ".css", ".js", ".ts", ".bat", ".sh", ".xml", ".toml"}

path_hits = {}
content_hits = {}
# 只是占位、里面没有真实数据的目录（发布时应当保留为空）
PLACEHOLDER_OK = (
    "app/DataBase/Msg", "app/DataBase/decrypted", "app/DataBase/export",
    "app/log/logs",
)


def dir_file_count(p: str) -> int:
    return sum(len(fs) for _r, _d, fs in os.walk(p))


def is_placeholder(rel: str) -> bool:
    rel = rel.rstrip("/")
    if rel not in PLACEHOLDER_OK:
        return False
    files = [f for _r, _d, fs in os.walk(rel) for f in fs]
    return all(f == ".gitkeep" for f in files)


for root, dirs, files in os.walk(ROOT):
    rel_root = os.path.relpath(root, ROOT).replace("\\", "/")
    if rel_root == ".":
        rel_root = ""
    for d in list(dirs):
        rel = ("%s/%s" % (rel_root, d)).lstrip("/")
        if is_placeholder(rel):
            path_hits.setdefault("空占位目录（正常，保留结构用）", []).append(rel + "/")
            continue
        for pat, why in PATTERN_RULES:
            if re.search(pat, rel + "/"):
                path_hits.setdefault(why, []).append(rel + "/")
    for f in files:
        rel = ("%s/%s" % (rel_root, f)).lstrip("/")
        full = os.path.join(root, f)
        if f == ".gitkeep":
            continue
        for pat, why in PATTERN_RULES:
            if re.search(pat, rel):
                path_hits.setdefault(why, []).append(rel)
        if os.path.splitext(f)[1].lower() in TEXT_EXT:
            if os.path.getsize(full) > 4 * 1024 * 1024:
                continue
            try:
                text = open(full, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for rx, why in CONTENT_RULES:
                m = rx.findall(text)
                if m:
                    content_hits.setdefault(why, {}).setdefault(rel, len(m))

print("=" * 74)
print("A. 按路径命中的“不该发布”文件/目录")
print("=" * 74)
if not path_hits:
    print("  （无）")
for why, items in sorted(path_hits.items(), key=lambda x: -len(x[1])):
    print("\n[%s] 共 %d 项" % (why, len(items)))
    for i in items[:12]:
        print("   -", i)
    if len(items) > 12:
        print("   ... 还有 %d 项" % (len(items) - 12))

print()
print("=" * 74)
print("B. 文本内容里出现的隐私痕迹（需要人工确认是否可接受）")
print("=" * 74)
if not content_hits:
    print("  （无）")
for why, files in sorted(content_hits.items()):
    print("\n[%s]" % why)
    for rel, n in sorted(files.items(), key=lambda x: -x[1])[:15]:
        print("   %-58s %d 处" % (rel, n))
    if len(files) > 15:
        print("   ... 还有 %d 个文件" % (len(files) - 15))
