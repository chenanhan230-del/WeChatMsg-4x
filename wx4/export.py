# -*- coding: utf-8 -*-
"""导出聊天记录：TXT / CSV / JSON / HTML。"""
from __future__ import annotations

import csv
import html
import json
import os
import re
from datetime import datetime

from .reader import Wx4Data

INVALID_FS = re.compile(r'[\\/:*?"<>|\r\n\t]')


def safe_name(name: str, maxlen: int = 60) -> str:
    name = INVALID_FS.sub("_", (name or "").strip())
    name = name.strip(" .")
    if not name:
        name = "unknown"
    return name[:maxlen]


def _ensure(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _media_line(m: dict, base_dir: str | None) -> str:
    """给一条消息附上媒体文件清单（相对路径）。"""
    items = []
    for p in (m.get("extra") or {}).get("images", []) or []:
        items.append(os.path.relpath(p, base_dir) if base_dir else os.path.basename(p))
    v = (m.get("extra") or {}).get("voice_file")
    if v:
        items.append(os.path.relpath(v, base_dir) if base_dir else os.path.basename(v))
    return "  [附件] " + " ; ".join(items) if items else ""


def _collect_media(data: Wx4Data, session: str, msgs: list, media_root: str,
                   aes_key=None, copy_dat: bool = True, progress=None) -> None:
    from . import media as media_mod
    media_mod.export_session_media(data, session, msgs,
                                   os.path.join(media_root, safe_name(
                                       data.session_display(session))),
                                   aes_key=aes_key, copy_dat=copy_dat,
                                   progress=progress)


# ---------------------------------------------------------------------------
# 单个会话
# ---------------------------------------------------------------------------
def export_txt(data: Wx4Data, session: str, out_path: str,
               media_base: str | None = None) -> str:
    msgs = data.messages(session)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("会话：%s (%s)\n" % (data.session_display(session), session))
        f.write("导出时间：%s  共 %d 条消息\n"
                % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(msgs)))
        f.write("=" * 70 + "\n\n")
        for m in msgs:
            who = "我" if m["is_sender"] else m["sender"]
            f.write("[%s] %s\n%s\n" % (m["time_str"], who, m["text"]))
            line = _media_line(m, media_base)
            if line:
                f.write(line + "\n")
            f.write("\n")
    return out_path


def export_csv(data: Wx4Data, session: str, out_path: str) -> str:
    msgs = data.messages(session)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "会话", "发送者", "是否我发送", "类型", "内容",
                    "server_id", "local_id", "分片"])
        for m in msgs:
            w.writerow([m["time_str"], data.session_display(session), m["sender"],
                        "是" if m["is_sender"] else "否", m["type_name"],
                        m["text"], m["server_id"], m["local_id"], m["shard"]])
    return out_path


def export_json(data: Wx4Data, session: str, out_path: str) -> str:
    msgs = data.messages(session)
    payload = {
        "session": session,
        "display": data.session_display(session),
        "wxid": data.wxid,
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "count": len(msgs),
        "messages": [_jsonable(m) for m in msgs],
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return out_path


def _jsonable(m: dict) -> dict:
    """把消息里的 bytes 换成字符串，保证 JSON 可序列化。"""
    out = {}
    for k, v in m.items():
        if isinstance(v, (bytes, bytearray)):
            out[k] = bytes(v).hex()
        elif isinstance(v, dict):
            out[k] = {kk: (vv.hex() if isinstance(vv, (bytes, bytearray)) else vv)
                      for kk, vv in v.items()}
        else:
            out[k] = v
    return out


HTML_CSS = """
body{font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif;background:#ededed;
     margin:0;padding:0 0 40px;}
header{position:sticky;top:0;background:#fff;border-bottom:1px solid #ddd;padding:12px 20px;
       z-index:10;}
header h1{font-size:17px;margin:0 0 4px;}
header .meta{font-size:12px;color:#888;}
.tools{margin-top:8px;}
.tools input{padding:6px 10px;border:1px solid #ccc;border-radius:6px;width:260px;font-size:13px;}
.tools button{padding:6px 12px;border:1px solid #ccc;background:#f7f7f7;border-radius:6px;
              cursor:pointer;font-size:13px;}
.tools button:hover{background:#eee;}
main{padding:16px 20px;max-width:900px;margin:0 auto;}
.msg{display:flex;margin:10px 0;gap:8px;}
.msg .who{flex:0 0 44px;height:44px;border-radius:6px;background:#c9c9c9;color:#fff;
          font-size:11px;display:flex;align-items:center;justify-content:center;overflow:hidden;}
.msg .who img{width:100%;height:100%;object-fit:cover;}
.bub{background:#fff;border-radius:8px;padding:8px 12px;max-width:640px;font-size:14px;
     line-height:1.55;white-space:pre-wrap;word-break:break-word;}
.msg .name{font-size:11px;color:#999;margin-bottom:3px;}
.msg .time{font-size:11px;color:#b0b0b0;margin-top:4px;}
.msg.me{flex-direction:row-reverse;}
.msg.me .bub{background:#95ec69;}
.msg.me .name,.msg.me .time{text-align:right;}
.sys{text-align:center;color:#999;font-size:12px;margin:12px 0;}
.attimg{max-width:260px;max-height:260px;border-radius:6px;display:block;margin-top:4px;}
.att{font-size:12px;color:#666;margin-top:4px;}
.att a{color:#1a73e8;}
.hidden{display:none;}
"""

HTML_JS = """
function flt(){var q=document.getElementById('q').value.trim().toLowerCase();
 var n=0;document.querySelectorAll('main .msg').forEach(function(e){
  var hit=!q||e.dataset.t.toLowerCase().indexOf(q)>=0;
  e.classList.toggle('hidden',!hit);if(hit)n++;});
 document.getElementById('cnt').textContent='显示 '+n+' 条';}
function toggleTime(){document.querySelectorAll('.time').forEach(function(e){
  e.classList.toggle('hidden');});}
"""


def _avatar_html(data: Wx4Data, username: str, label: str) -> str:
    url = data.avatar_of(username)
    if url:
        return ('<div class="who"><img loading="lazy" src="%s" alt=""></div>'
                % html.escape(url, quote=True))
    return '<div class="who">%s</div>' % html.escape(label[:2])


def _media_html(m: dict, base_dir: str | None) -> str:
    """把已导出的图片/语音嵌进气泡。"""
    if not base_dir:
        return ""
    out = []
    for p in (m.get("extra") or {}).get("images", []) or []:
        rel = os.path.relpath(p, base_dir).replace("\\", "/")
        if rel.lower().endswith(".dat"):
            out.append("<div class='att'>[图片未解密] <a href='%s'>%s</a></div>"
                       % (html.escape(rel, quote=True), html.escape(os.path.basename(rel))))
        else:
            out.append("<a href='%s'><img class='attimg' loading='lazy' src='%s'></a>"
                       % (html.escape(rel, quote=True), html.escape(rel, quote=True)))
    v = (m.get("extra") or {}).get("voice_file")
    if v:
        rel = os.path.relpath(v, base_dir).replace("\\", "/")
        out.append("<div class='att'>[语音 silk] <a href='%s'>%s</a></div>"
                   % (html.escape(rel, quote=True), html.escape(os.path.basename(rel))))
    return "".join(out)


def export_html(data: Wx4Data, session: str, out_path: str,
                include_time: bool = True, media_base: str | None = None) -> str:
    msgs = data.messages(session)
    display = data.session_display(session)
    parts = [
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>%s - 聊天记录</title>" % html.escape(display),
        "<style>%s</style></head><body>" % HTML_CSS,
        "<header><h1>%s</h1>" % html.escape(display),
        "<div class='meta'>%s · 共 %d 条 · 导出 %s</div>"
        % (html.escape(session), len(msgs),
           datetime.now().strftime("%Y-%m-%d %H:%M")),
        "<div class='tools'><input id='q' placeholder='搜索消息内容…' oninput='flt()'> "
        "<button onclick='flt()'>搜索</button> "
        "<button onclick='toggleTime()'>显示/隐藏时间</button> "
        "<span class='meta' id='cnt'></span></div></header><main>",
    ]
    for m in msgs:
        if m["kind"] == "system":
            parts.append("<div class='msg' data-t='%s'><div class='sys'>%s</div></div>"
                         % (html.escape(m["text"].lower()),
                            html.escape(m["text"])))
            continue
        cls = "msg me" if m["is_sender"] else "msg"
        who = "我" if m["is_sender"] else m["sender"]
        av = _avatar_html(data, m["sender_wxid"] or session, who)
        tm = ("<div class='time'%s>%s</div>"
              % ("" if include_time else " style='display:none'", m["time_str"]))
        extra = _media_html(m, media_base)
        parts.append(
            "<div class='%s' data-t='%s'>%s<div><div class='name'>%s</div>"
            "<div class='bub'>%s%s</div>%s</div></div>"
            % (cls, html.escape(m["text"].lower()), av, html.escape(who),
               html.escape(m["text"]), extra, tm))
    parts.append("</main><script>%s</script></body></html>" % HTML_JS)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return out_path


# ---------------------------------------------------------------------------
# 批量
# ---------------------------------------------------------------------------
EXPORTERS = {
    "txt": export_txt,
    "csv": export_csv,
    "json": export_json,
    "html": export_html,
}


def export_all(data: Wx4Data, out_dir: str, fmt: str = "html",
               sessions: list[str] | None = None, progress=None,
               only_with_messages: bool = True, media: bool = False,
               copy_dat: bool = True, aes_key=None) -> dict:
    """把（选定的）会话逐个导出。

    media=True 时额外把图片/语音导出到 <out_dir>/media/<会话>/ 下，
    HTML/TXT 里会带上附件链接。
    """
    progress = progress or (lambda m: None)
    _ensure(out_dir)
    if sessions is None:
        sessions = [s["username"] for s in data.sessions()]
    if only_with_messages:
        sessions = [s for s in sessions if data.has_messages(s)]
    media_root = os.path.join(out_dir, "media") if media else None
    if media:
        _ensure(media_root)
        from . import media as media_mod
        nv, nf = media_mod.copy_plain_media(data, media_root, progress=progress)
        progress("视频 %d 个、文件 %d 个已复制" % (nv, nf))
    done, empty = [], []
    for i, s in enumerate(sessions, 1):
        msgs = data.messages(s)
        if not msgs:
            empty.append(s)
            continue
        display = safe_name(data.session_display(s))
        fname = "%s_%s.%s" % (display, s[:24].replace("@", "_at_"), fmt)
        path = os.path.join(out_dir, fname)
        try:
            if media:
                sess_media = os.path.join(media_root, display)
                _collect_media(data, s, msgs, media_root, aes_key=aes_key,
                               copy_dat=copy_dat, progress=progress)
                # 采集媒体会往 msgs 里写 extra，需要重新取一遍正文
                msgs = data.messages(s)
            if fmt == "html":
                export_html(data, s, path, media_base=media_root)
            elif fmt == "txt":
                export_txt(data, s, path, media_base=media_root)
            else:
                EXPORTERS[fmt](data, s, path)
            done.append(path)
            progress("[%d/%d] %s -> %s" % (i, len(sessions), display,
                                           os.path.basename(path)))
        except Exception as e:                            # noqa: BLE001
            progress("[%d/%d] %s 失败：%s" % (i, len(sessions), display, e))
    progress("完成：%d 个会话已导出，%d 个无消息" % (len(done), len(empty)))
    return {"exported": done, "empty": empty, "out_dir": out_dir}


def export_index(data: Wx4Data, out_dir: str, fmt: str = "html",
                 progress=None) -> str:
    """生成会话索引页，方便逐条点开。"""
    sessions = [s for s in data.sessions() if data.has_messages(s["username"])]
    rows = []
    for s in sessions:
        display = safe_name(data.session_display(s["username"]))
        fname = "%s_%s.%s" % (display, s["username"][:24].replace("@", "_at_"), fmt)
        t = (datetime.fromtimestamp(s["sort_time"]).strftime("%Y-%m-%d %H:%M")
             if s["sort_time"] else "")
        rows.append("<tr><td><a href='%s'>%s</a></td><td>%s</td><td>%s</td>"
                    "<td>%s</td></tr>"
                    % (html.escape(fname), html.escape(s["display"]),
                       html.escape(s["username"]), html.escape(t),
                       html.escape(s["summary"][:60])))
    doc = ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
           "<title>聊天记录索引</title><style>body{font-family:'Microsoft YaHei',"
           "sans-serif;padding:20px;}table{border-collapse:collapse;width:100%;}"
           "td,th{border-bottom:1px solid #eee;padding:6px 10px;font-size:13px;"
           "text-align:left;}a{color:#1a73e8;text-decoration:none;}</style></head>"
           "<body><h2>聊天记录索引（" + str(len(rows)) + " 个会话）</h2>"
           "<table><tr><th>会话</th><th>wxid</th><th>最后消息时间</th>"
           "<th>摘要</th></tr>" + "".join(rows) + "</table></body></html>")
    path = os.path.join(out_dir, "index.html")
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    if progress:
        progress("索引页：%s" % path)
    return path
