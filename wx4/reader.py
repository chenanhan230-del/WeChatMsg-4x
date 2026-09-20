# -*- coding: utf-8 -*-
"""微信 4.x 数据读取层。

把解密后的库读成「会话 + 消息」模型：

    session.db           -> SessionTable（会话列表、最后一条消息）
    contact.db           -> contact / stranger / chat_room / chatroom_member
    message_N.db         -> Msg_<md5(会话)>，每个会话一张表，跨分片
    biz_message_N.db     -> 同上（公众号/服务号）
    media_N.db           -> VoiceInfo（语音 SILK 数据）
    message_resource.db  -> 文件原名等资源信息

与 3.x 的关键差异见 doc/微信4.x适配说明.md。
"""
from __future__ import annotations

import hashlib
import html
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    import zstandard as zstd
    _ZSTD = zstd.ZstdDecompressor()
except ImportError:                                     # pragma: no cover
    _ZSTD = None

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# ---------------------------------------------------------------------------
# 消息类型表
# ---------------------------------------------------------------------------
TYPE_NAMES = {
    1: "文本", 3: "图片", 34: "语音", 37: "好友请求", 42: "名片", 43: "视频",
    47: "动画表情", 48: "位置", 49: "应用消息", 50: "音视频通话", 51: "状态",
    62: "小视频", 66: "连线", 10000: "系统消息", 10002: "系统消息",
    11000: "动画表情", 11001: "引用消息", 11002: "文件",
}

APPMSG_SUBTYPE = {
    1: "文本", 2: "图片", 3: "音乐", 4: "视频", 5: "链接", 6: "文件",
    7: "合并转发", 8: "动画表情", 9: "小程序", 10: "视频号", 11: "视频号直播",
    13: "卡包", 14: "聊天记录", 15: "位置共享", 16: "音乐", 17: "位置共享",
    19: "合并转发聊天记录", 20: "聊天记录", 21: "卡包", 24: "笔记",
    33: "小程序", 36: "小程序", 44: "微信红包封面", 48: "视频号",
    51: "视频号直播", 53: "接龙", 57: "引用消息", 62: "视频号",
    63: "直播", 87: "群公告", 88: "直播",
    2000: "转账", 2001: "转账", 2003: "红包",
}

KNOWN_BASE_TYPES = set(TYPE_NAMES) | set(range(1, 100)) | {10000, 10002}


def normalize_local_type(t) -> int:
    """4.x 的 local_type 可能是 (subtype << 32) | base_type 的复合值。"""
    try:
        t = int(t)
    except (TypeError, ValueError):
        return 0
    if t <= 0xFFFF:
        return t
    base = t & 0xFFFFFFFF
    if base in KNOWN_BASE_TYPES:
        return base
    return base & 0xFF


def _xml(text: str):
    """容错解析微信 XML（正文里常含裸 & 等非法字符）。"""
    if not text:
        return None
    s = text.strip()
    i = s.find("<")
    if i < 0:
        return None
    s = s[i:]
    try:
        return ET.fromstring(s)
    except ET.ParseError:
        pass
    fixed = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", s)
    try:
        return ET.fromstring(fixed)
    except ET.ParseError:
        return None


def _txt(root, path, default="") -> str:
    """取文本。path 先按绝对路径找，找不到再按「任意深度」找。

    微信的 XML 是 `<msg><appmsg><title>..` 这种嵌套结构，直接 root.find('title')
    是找不到的，因此这里统一用 .// 兜底。
    """
    if root is None:
        return default
    for candidate in (path, ".//" + path.lstrip("./")):
        node = root.find(candidate)
        if node is not None and node.text is not None:
            return node.text
    return default


def _find(root, path):
    if root is None:
        return None
    for candidate in (path, ".//" + path.lstrip("./")):
        node = root.find(candidate)
        if node is not None:
            return node
    return None


# ---------------------------------------------------------------------------
# 内容解码
# ---------------------------------------------------------------------------
def to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if b[:4] == ZSTD_MAGIC:
            if _ZSTD is None:
                return ""
            try:
                return _ZSTD.decompress(b, max_output_size=4 * 1024 * 1024).decode(
                    "utf-8", "ignore")
            except Exception:                            # noqa: BLE001
                return ""
        txt = b.decode("utf-8", "ignore")
        # 「短容器头 + 明文 + \x01\x00 尾」的裸文本
        start = txt.find("<")
        if 0 < start <= 24 and len(txt) > start:
            txt = txt[start:]
        end = txt.find("\x01\x00")
        if end > 0:
            txt = txt[:end]
        return txt
    return str(value)


def decode_content(message_content, compress_content) -> str:
    """按 4.x 规则取正文：ZSTD 解压 / compress_content / 裸文本。"""
    for blob in (message_content, compress_content):
        if isinstance(blob, (bytes, bytearray)) and bytes(blob)[:4] == ZSTD_MAGIC:
            t = to_text(blob)
            if t:
                return html.unescape(t) if "&" in t else t
    for blob in (compress_content, message_content):
        t = to_text(blob)
        if t and t.strip():
            t = t.strip()
            return html.unescape(t) if "&" in t else t
    return ""


def _display_name(row) -> str:
    if not row:
        return ""
    for key in ("remark", "nick_name", "alias", "username"):
        v = row.get(key) if isinstance(row, dict) else None
        if v:
            return v
    return ""


class Wx4Data:
    """解密后数据的统一访问入口。"""

    def __init__(self, decrypted_dir: str, wxid: str = "", progress=None,
                 account_dir: str | None = None):
        self.root = decrypted_dir
        self.wxid = wxid
        self.progress = progress or (lambda m: None)
        # 原始账号目录（含 msg/ 附件）。解密输出与微信数据不在同一棵树时由调用方
        # 显式指定；否则按 <decrypted_dir>/.. 猜。
        self._account_dir = account_dir
        self._conns: dict[str, sqlite3.Connection | None] = {}
        self._tables: dict[int, set] = {}
        self.contacts: dict[str, dict] = {}
        self.room_members: dict[str, list[str]] = {}
        self.me: dict = {}
        self.msg_dbs: list[sqlite3.Connection] = []
        self.media_dbs: list[sqlite3.Connection] = []
        self._scan_dbs()
        self._load_contacts()
        self._load_rooms()

    # -- 库发现与连接 ------------------------------------------------------
    def _scan_dbs(self):
        msg_found: list[tuple[str, sqlite3.Connection]] = []
        media_found: list[tuple[str, sqlite3.Connection]] = []
        for root, _dirs, files in os.walk(self.root):
            for f in files:
                if not f.endswith(".db"):
                    continue
                rel = os.path.relpath(os.path.join(root, f), self.root)
                base = re.sub(r"\s*\([^)]*\)\.db$", ".db", f)   # 时间戳副本
                con = self._open(rel)
                if con is None:
                    continue
                if re.match(r"^message_(\d+)?\.db$", base) or \
                   re.match(r"^biz_message_(\d+)?\.db$", base):
                    msg_found.append((rel, con))
                elif re.match(r"^media_(\d+)?\.db$", base):
                    media_found.append((rel, con))
        msg_found.sort(key=lambda x: x[0])
        media_found.sort(key=lambda x: x[0])
        self.msg_dbs = [c for _rel, c in msg_found]
        self.media_dbs = [c for _rel, c in media_found]
        self.progress("装载 %d 个消息库、%d 个语音库" % (len(self.msg_dbs), len(self.media_dbs)))

    def _open(self, rel: str):
        if rel in self._conns:
            return self._conns[rel]
        path = os.path.join(self.root, rel)
        con = None
        if os.path.exists(path):
            try:
                con = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"),
                                      uri=True)
                con.row_factory = sqlite3.Row
                self._tables[id(con)] = {
                    r[0] for r in con.execute(
                        "select name from sqlite_master where type='table'")}
            except sqlite3.Error:
                con = None
        self._conns[rel] = con
        return con

    def _db_rel(self, name_no_ext: str) -> str | None:
        """精确匹配（忽略时间戳副本后缀）。"""
        for rel in self._iter_db_rel():
            base = re.sub(r"\s*\([^)]*\)\.db$", ".db", os.path.basename(rel))
            if base == name_no_ext + ".db":
                return rel
        return None

    def _iter_db_rel(self):
        for root, _dirs, files in os.walk(self.root):
            for f in files:
                if f.endswith(".db"):
                    yield os.path.relpath(os.path.join(root, f), self.root)

    def tables_of(self, con) -> set:
        return self._tables.get(id(con), set())

    def close(self):
        for con in self._conns.values():
            if con is not None:
                try:
                    con.close()
                except sqlite3.Error:
                    pass
        self._conns.clear()

    # -- 联系人 ------------------------------------------------------------
    def _contact_con(self):
        rel = self._db_rel("contact")
        return self._open(rel) if rel else None

    def _load_contacts(self):
        con = self._contact_con()
        if con is None:
            self.progress("未找到 contact.db")
            return
        for table in ("contact", "stranger"):
            if table not in self.tables_of(con):
                continue
            try:
                rows = con.execute(
                    "select id,username,local_type,alias,remark,nick_name,"
                    "big_head_url,small_head_url,description from %s" % table)
            except sqlite3.Error:
                continue
            for r in rows:
                d = dict(r)
                d["_table"] = table
                if d.get("id") is not None:
                    self.contacts.setdefault("#id:%s" % d["id"], d)
                self.contacts.setdefault(d["username"], d)
        if self.wxid:
            self.me = self.contacts.get(self.wxid) or {}
        self.progress("装载 %d 条联系人记录" % len(self.contacts))

    def _load_rooms(self):
        con = self._contact_con()
        if con is None:
            return
        try:
            room_ids = {r["id"]: r["username"]
                        for r in con.execute("select id,username from chat_room")}
            rows = con.execute("select room_id,member_id from chatroom_member").fetchall()
        except sqlite3.Error:
            return
        for r in rows:
            room = room_ids.get(r["room_id"])
            if not room:
                continue
            m = self.contacts.get("#id:%s" % r["member_id"])
            if m:
                self.room_members.setdefault(room, []).append(m["username"])
        self.progress("装载 %d 个群的成员列表" % len(self.room_members))

    # -- 名字 --------------------------------------------------------------
    def name_of(self, username: str) -> str:
        if not username:
            return ""
        n = _display_name(self.contacts.get(username))
        if n:
            return n
        if username == self.wxid:
            return "我"
        return username

    def avatar_of(self, username: str) -> str:
        c = self.contacts.get(username) or {}
        return c.get("big_head_url") or c.get("small_head_url") or ""

    def session_display(self, username: str) -> str:
        n = self.name_of(username)
        if n == username and username.endswith("@chatroom"):
            members = self.room_members.get(username) or []
            if members:
                names = [self.name_of(m) for m in members[:3]]
                return "%s(%d人)" % ("、".join(names), len(members))
            return username.replace("@chatroom", "")
        return n

    # -- 会话 --------------------------------------------------------------
    def sessions(self) -> list[dict]:
        rel = self._db_rel("session")
        con = self._open(rel) if rel else None
        if con is None or "SessionTable" not in self.tables_of(con):
            return []
        cols = {r[1] for r in con.execute("pragma table_info(SessionTable)")}
        order = "sort_timestamp" if "sort_timestamp" in cols else "last_timestamp"
        out = []
        for r in con.execute("select * from SessionTable order by %s desc" % order):
            d = dict(r)
            username = d.get("username") or ""
            if not username:
                continue
            out.append({
                "username": username,
                "display": self.session_display(username),
                "unread": d.get("unread_count") or 0,
                "summary": to_text(d.get("summary"))[:120],
                "last_time": d.get("last_timestamp") or 0,
                "sort_time": d.get("sort_timestamp") or d.get("last_timestamp") or 0,
                "is_group": username.endswith("@chatroom"),
                "last_sender": d.get("last_msg_sender") or "",
                "last_type": d.get("last_msg_type") or 0,
            })
        out.sort(key=lambda x: x["sort_time"], reverse=True)
        return out

    # -- 消息 --------------------------------------------------------------
    @staticmethod
    def msg_table_for(username: str) -> str:
        return "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()

    @staticmethod
    def _name2id(con) -> dict:
        try:
            return {r[0]: r[1] for r in con.execute("select rowid,user_name from Name2Id")}
        except sqlite3.Error:
            return {}

    def has_messages(self, username: str) -> bool:
        t = self.msg_table_for(username)
        for con in self.msg_dbs:
            if t in self.tables_of(con):
                return True
        return False

    def messages(self, username: str, limit: int | None = None,
                 start: int | None = None, end: int | None = None,
                 ascending: bool = True) -> list[dict]:
        """取某会话消息。片内按 (sort_seq, local_id) 排，跨片按时间归并。"""
        table = self.msg_table_for(username)
        out = []
        for shard, con in enumerate(self.msg_dbs):
            if table not in self.tables_of(con):
                continue
            id2name = self._name2id(con)
            try:
                rows = con.execute(
                    "select local_id,server_id,local_type,sort_seq,real_sender_id,"
                    "create_time,message_content,compress_content,packed_info_data "
                    'from "%s" order by sort_seq asc, local_id asc' % table).fetchall()
            except sqlite3.Error:
                continue
            for r in rows:
                ct = r["create_time"] or 0
                if start and ct < start:
                    continue
                if end and ct > end:
                    continue
                out.append(self._build_msg(r, id2name, username, shard))
        out.sort(key=lambda m: (m["create_time"], m["shard"], m["local_id"]))
        if limit:
            out = out[-limit:] if ascending else out[:limit]
        return out

    def _build_msg(self, r, id2name, session, shard) -> dict:
        raw_type = r["local_type"]
        mtype = normalize_local_type(raw_type)
        content = decode_content(r["message_content"], r["compress_content"])
        sender = id2name.get(r["real_sender_id"], "")
        # 群消息正文常以 "wxid:\n" 开头，可自证发送者
        if content[:1] and "\n" in content[:80]:
            head, rest = content.split("\n", 1)
            if head.endswith(":"):
                maybe = head[:-1].strip()
                if maybe and ("@" in maybe or maybe.startswith("wxid_")) and " " not in maybe:
                    if not sender:
                        sender = maybe
                    content = rest
        msg = {
            "local_id": r["local_id"],
            "server_id": r["server_id"],
            "shard": shard,
            "type": mtype,
            "raw_type": raw_type,
            "type_name": TYPE_NAMES.get(mtype, "其他(%s)" % mtype),
            "create_time": r["create_time"] or 0,
            "time_str": (datetime.fromtimestamp(r["create_time"]).strftime(
                "%Y-%m-%d %H:%M:%S") if r["create_time"] else ""),
            "sender_wxid": sender,
            "sender": self.name_of(sender) if sender else "系统",
            "is_sender": bool(sender) and sender == self.wxid,
            "content": content,
            "session": session,
            "packed_hex": (bytes(r["packed_info_data"]).hex()
                           if r["packed_info_data"] else ""),
        }
        msg.update(self._describe(msg))
        return msg

    # -- 按类型生成可读文本 ------------------------------------------------
    def _describe(self, msg: dict) -> dict:
        mtype = msg["type"]
        content = msg["content"]
        out = {"text": content, "extra": {}}
        if mtype == 1:
            out["kind"] = "text"
        elif mtype == 3:
            out["kind"] = "image"
            out["text"] = "[图片]"
        elif mtype in (43, 62):
            out["kind"] = "video"
            out["text"] = "[视频]"
        elif mtype == 34:
            out["kind"] = "voice"
            root = _xml(content)
            sec = _txt(root, "voicelength")
            out["extra"]["voice_length"] = sec
            dur = ""
            if sec.isdigit():
                dur = "%d\"" % (int(sec) // 1000)
            out["text"] = "[语音%s]" % dur
        elif mtype in (47, 11000):
            out["kind"] = "emoji"
            out["text"] = "[动画表情]"
        elif mtype == 42:
            out["kind"] = "card"
            out["text"] = "[名片] %s" % _txt(_xml(content), "nickname")
        elif mtype == 48:
            out["kind"] = "location"
            root = _xml(content)
            out["text"] = "[位置] %s %s" % (_txt(root, "poiname"), _txt(root, "label"))
        elif mtype == 50:
            out["kind"] = "voip"
            out["text"] = "[音视频通话]"
        elif mtype == 10000:
            out["kind"] = "system"
            out["text"] = self._system_text(content)
        elif mtype == 49:
            return self._describe_appmsg(msg, out)
        else:
            out["kind"] = "other"
            out["text"] = "[%s]" % msg["type_name"]
        return out

    @staticmethod
    def _system_text(content: str) -> str:
        root = _xml(content)
        if root is None:
            return content or "[系统消息]"
        node = _find(root, "content")
        if node is not None and node.text:
            return node.text
        return content or "[系统消息]"

    def _describe_appmsg(self, msg: dict, out: dict) -> dict:
        content = msg["content"]
        root = _xml(content)
        if root is None:
            out["kind"] = "other"
            out["text"] = "[应用消息]"
            return out
        sub = _txt(root, "type")
        try:
            sub_i = int(sub)
        except (TypeError, ValueError):
            sub_i = 0
        title = _txt(root, "title")
        desc = _txt(root, "des")
        url = _txt(root, "url")
        kind = APPMSG_SUBTYPE.get(sub_i, "应用消息(%s)" % sub)
        out["extra"].update({"appmsg_type": sub_i, "title": title, "url": url})

        if sub_i == 57:
            refer = _find(root, "refermsg")
            out["kind"] = "quote"
            if refer is not None:
                rname = _txt(refer, "displayname")
                rtext = self._refer_text(_txt(refer, "content"))
                out["extra"]["refer_from"] = _txt(refer, "fromusr")
                out["text"] = "%s\n  ↳ %s: %s" % (title or content, rname, rtext)
            else:
                out["text"] = title or "[引用消息]"
            return out

        if sub_i in (19, 20, 7, 14):
            rec = _find(root, "recorditem")
            items = []
            if rec is not None and rec.text:
                inner = _xml(rec.text)
                if inner is not None:
                    for item in inner.findall(".//dataitem"):
                        items.append(_txt(item, "sourcename") or _txt(item, "datadesc"))
            out["kind"] = "chatrecord"
            joined = " / ".join(i for i in items[:5] if i)
            out["text"] = "[聊天记录] %s%s" % (title, ("：%s" % joined) if joined else "")
            return out

        if sub_i == 6:
            attach = _find(root, "appattach")
            fname = _txt(attach, "filename") if attach is not None else ""
            size = _txt(attach, "totallen") if attach is not None else ""
            out["kind"] = "file"
            out["extra"].update({"filename": fname or title, "filesize": size})
            out["text"] = "[文件] %s" % (fname or title or desc)
            return out

        simple = {
            2003: ("hongbao", "[微信红包]"), 2000: ("transfer", "[转账]"),
            2001: ("transfer", "[转账]"), 5: ("link", "[链接]"),
            33: ("miniprogram", "[小程序]"), 36: ("miniprogram", "[小程序]"),
            44: ("miniprogram", "[小程序]"), 63: ("live", "[直播]"),
            88: ("live", "[直播]"), 51: ("live", "[直播]"),
            11: ("live", "[直播]"), 87: ("announce", "[群公告]"),
        }
        if sub_i in simple:
            k, label = simple[sub_i]
            out["kind"] = k
            tail = url if k == "link" else (title or desc)
            out["text"] = "%s %s" % (label, tail)
            return out

        out["kind"] = "appmsg"
        out["text"] = "[%s] %s %s" % (kind, title, desc)
        return out

    @staticmethod
    def _refer_text(rtext: str) -> str:
        if not rtext:
            return ""
        root = _xml(rtext)
        if root is not None:
            t = _txt(root, "title")
            if t:
                return t
        return rtext

    # -- 语音 --------------------------------------------------------------
    def voice_blob(self, session: str, server_id: int):
        """按 server_id 从 media_*.db 取 SILK 语音数据。"""
        for con in self.media_dbs:
            if "VoiceInfo" not in self.tables_of(con):
                continue
            try:
                r = con.execute("select rowid from Name2Id where user_name=?",
                                (session,)).fetchone()
            except sqlite3.Error:
                continue
            if not r:
                continue
            try:
                row = con.execute(
                    "select voice_data from VoiceInfo where chat_name_id=? and svr_id=? "
                    "order by create_time desc limit 1", (r[0], server_id)).fetchone()
            except sqlite3.Error:
                continue
            if row and row[0]:
                return bytes(row[0])
        return None

    # -- 附件目录 ----------------------------------------------------------
    def account_dir(self) -> str:
        return self._account_dir or os.path.dirname(self.root.rstrip("\\/"))

    def msg_dir(self) -> str:
        return os.path.join(self.account_dir(), "msg")

    def attach_dir(self, session: str) -> str | None:
        h = hashlib.md5(session.encode("utf-8")).hexdigest()
        p = os.path.join(self.msg_dir(), "attach", h)
        return p if os.path.isdir(p) else None


def open_data(decrypted_dir: str, wxid: str = "", progress=None,
              account_dir: str | None = None) -> Wx4Data:
    return Wx4Data(decrypted_dir, wxid, progress, account_dir)
