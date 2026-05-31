"""Query the local SQLite archive WITHOUT connecting to WhatsApp.

Reads a piwapp SQLite DB (written when a Client runs with db_path / by
history_dump.py) and answers questions offline.

Usage:
  python scripts/query.py [db]                 # summary + last sent + recent chats
  python scripts/query.py [db] chat <jid> [n]  # last n messages in a chat
  python scripts/query.py [db] search <text>   # full-text-ish search
"""

from __future__ import annotations

import sys
from datetime import datetime

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from piwapp.store import SqliteStore


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "?"


def main() -> int:
    db = sys.argv[1] if len(sys.argv) > 1 else "piwapp_hist.json.db"
    store = SqliteStore(db)
    cmd = sys.argv[2] if len(sys.argv) > 2 else None

    if cmd == "chat":
        jid = sys.argv[3]
        n = int(sys.argv[4]) if len(sys.argv) > 4 else 20
        for m in reversed(store.get_chat_messages(jid, n)):
            arrow = "->" if m["key"]["fromMe"] else "<-"
            print(f"  [{_when(m['messageTimestamp'])}] {arrow} {m['text']!r}")
        return 0

    if cmd == "search":
        for m in store.search_text(sys.argv[3]):
            print(f"  [{_when(m['messageTimestamp'])}] {m['key']['remoteJid']}: {m['text']!r}")
        return 0

    # default summary
    print(f"DB: {db}")
    print(f"messages stored: {store.message_count}")
    last = store.last_sent_message()
    if last:
        print("\nlast message YOU sent:")
        print(f"  to:   {last['key']['remoteJid']}")
        print(f"  when: {_when(last['messageTimestamp'])}")
        print(f"  text: {last['text']!r}")
    print("\nrecent chats:")
    for c in store.recent_chats(15):
        print(f"  {c['jid']}  {c.get('name')!r}  (t={c.get('conversation_timestamp')})")
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
