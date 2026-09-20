# -*- coding: utf-8 -*-
"""诊断：打印若干消息的原始 message_content / compress_content / packed_info_data。"""
import io
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from wx4.reader import decode_content, normalize_local_type

BASE = sys.argv[1] if len(sys.argv) > 1 else "tools/decrypted"
WANT_TABLE = sys.argv[2] if len(sys.argv) > 2 else ""
N = int(sys.argv[3]) if len(sys.argv) > 3 else 8
WANT_TYPE = int(sys.argv[4]) if len(sys.argv) > 4 else 0

INTEREST = {49, 3, 34, 43, 47, 48, 42, 10000, 11000, 11001, 50}
types = {}
seen = 0


def db_files():
    out = []
    for root, _d, files in os.walk(BASE):
        for f in files:
            if "message_" in f and f.endswith(".db") and "-" not in f:
                out.append(os.path.join(root, f))
    return sorted(out)


for path in db_files():
    con = sqlite3.connect(path)
    names = [n for (n,) in con.execute(
        "select name from sqlite_master where type='table' and name like 'Msg_%'")]
    for name in names:
        if WANT_TABLE and WANT_TABLE not in name:
            continue
        for r in con.execute(
                'select local_id,local_type,real_sender_id,create_time,message_content,'
                'compress_content,packed_info_data from "%s"' % name):
            t = normalize_local_type(r[1])
            types[t] = types.get(t, 0) + 1
            if WANT_TYPE:
                if t != WANT_TYPE:
                    continue
            elif t not in INTEREST:
                continue
            if seen >= N:
                continue
            seen += 1
            print("=" * 72)
            print("db=%s table=%s local_id=%s raw_type=%s norm_type=%s sender=%s time=%s"
                  % (os.path.basename(path), name, r[0], r[1], t, r[2], r[3]))
            mc, cc, pi = r[4], r[5], r[6]
            print("  mc  type=%s len=%s" % (type(mc).__name__,
                                            len(mc) if mc is not None else 0))
            print("  raw mc : %r" % (mc[:200] if isinstance(mc, (bytes, str)) else mc))
            print("  raw cc : %r" % (cc[:200] if isinstance(cc, (bytes, str)) else cc))
            print("  packed : %r" % (bytes(pi)[:80] if pi else None))
            print("  decode : %r" % decode_content(mc, cc)[:400])
    con.close()

print("\n=== 类型分布 ===")
for t, c in sorted(types.items(), key=lambda x: -x[1])[:30]:
    print("  %-10s %d" % (t, c))
