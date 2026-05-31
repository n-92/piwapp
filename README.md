# piwapp

**Talk to WhatsApp from Python and let an AI do it for you.**

piwapp is a WhatsApp client written entirely in Python. You link it to your phone
by scanning a QR code (just like WhatsApp Web), and from then on your code can
send and receive messages, media, and group chats. It also ships an **MCP server**
so assistants like Claude or GitHub Copilot can read and send your WhatsApp
messages in plain English.

It is purely built on Python

**No browser automation, no Node.js, no Go bridge.** Pure Python, all the way
down to the encryption.

> **Status:** working and live-tested against real WhatsApp. QR login, staying
> online, sending/receiving 1:1 **and group** messages, media (images, video,
> audio, documents), chat-history sync, and the MCP server have all been verified
> against the real service.

---

## What you can do

- 🔗 **Link your account** with a QR code and stay connected (auto-reconnect).
- 💬 **Send & receive text** — direct chats and groups.
- 🖼️ **Send & receive media** — images, video, audio, documents (encrypted +
  uploaded/downloaded for you).
- 👥 **Groups, first-class** — list your groups, send to them, decrypt everyone's
  messages.
- 🗂️ **Keep history** — messages save to a local SQLite database you can query
  offline.
- 🤖 **Hook it up to an LLM** — the built-in MCP server lets Claude/Copilot chat
  on WhatsApp for you.

---

## Install

Requires **Python 3.12+**.

```bash
git clone <your-repo-url> piwapp && cd piwapp
pip install -e ".[mcp]"      # ".[mcp]" includes the MCP server; use ".[dev]" for tests
```

---

## 60-second quick start (no code)

```bash
python -m piwapp            # creates/uses ./piwapp_auth.json
```

A QR code prints in your terminal (and saves to `piwapp_qr.png`). Scan it with
**WhatsApp → Linked Devices → Link a Device**. You'll see `✓ Online as <you>` and
incoming messages will start printing. Next time you run it, it logs straight back
in — no QR needed.

---

## Use it from Python

### Connect and stay online

```python
import asyncio
from pathlib import Path
from piwapp import Client, ConnectionConfig, AuthenticationCreds

auth = Path("my_account.json")

def load_creds():
    if auth.exists():
        return AuthenticationCreds.from_json(auth.read_text())
    creds = AuthenticationCreds.initial()
    auth.write_text(creds.to_json())
    return creds

async def main():
    client = Client(
        load_creds(),
        ConnectionConfig(),
        on_creds_update=lambda c: auth.write_text(c.to_json()),  # save login
        keys_path="my_account.json.keys",                        # save encryption keys
        db_path="my_account.db",                                 # save messages (optional)
    )
    client.on("connection.update", on_connection)
    await client.start()          # connects and reconnects until you stop it

async def on_connection(update: dict):
    if "qr" in update:
        print("Scan this QR:", update["qr"])      # or render/save it as an image
    if update.get("connection") == "open":
        print("online as", (update.get("me") or {}).get("id"))

asyncio.run(main())
```

### Receive messages

```python
from piwapp.events import WAEventType

def on_messages(payload):
    for m in payload.messages:
        chat   = m["key"]["remoteJid"]                 # who/which group it's from
        sender = m["key"].get("participant") or chat
        text   = m.get("text")                         # decoded text (or caption)
        if m.get("media"):
            print(f"{sender} sent a {m['media']['type']}: {text!r}")
        else:
            print(f"{sender}: {text!r}")

client.events.on(WAEventType.MESSAGES_UPSERT, on_messages)
```

### Send a message (once you're online)

```python
# direct message — phone number in international format, no "+"
await client.send_text("15551234567@s.whatsapp.net", "hello from piwapp 🐍")

# a group — send_text auto-detects the @g.us address
await client.send_text("120363XXXXXXXXXXXX@g.us", "hi everyone!")

# list the groups you're in
groups = await client.fetch_groups()    # [{id, subject, size, ...}, ...]
```

### Send a file or image

```python
# straight from a path (type is guessed from the extension)
await client.send_file("15551234567@s.whatsapp.net", "vacation.jpg", caption="📸")

# or from bytes you already have
await client.send_media("120363XXXXXXXXXXXX@g.us", img_bytes,
                        mimetype="image/png", caption="for the group")
```

### Download media you received

```python
# `m` is one message dict from a MESSAGES_UPSERT payload
async def save_attachment(m):
    if m.get("media"):
        data = await client.download_media(m["message"])   # decrypts + verifies hashes
        Path("downloaded.bin").write_bytes(data)
```

### Read your saved history (even offline)

If you passed `db_path`, every message is stored in SQLite. You can query it any
time — no connection required:

```python
from piwapp.store import SqliteStore

db = SqliteStore("my_account.db")
db.last_sent_message()                       # the last thing you sent
db.recent_chats(20)                          # most recent conversations
db.get_chat_messages("120363...@g.us", 50)   # recent messages in a chat
db.search_text("invoice")                    # find messages containing text
```

There's also a CLI helper: `python scripts/query.py my_account.db`.

---

## Use it from an LLM (the MCP server)

This is the fun part. piwapp ships a
[Model Context Protocol](https://modelcontextprotocol.io) server, so an assistant
(Claude Code, Claude Desktop, GitHub Copilot agent mode, …) can use your WhatsApp
with natural language: *"text Mom I'm running late"*, *"what did the team group say
today?"*, *"watch the group and reply to anyone who messages."*

### Setup (3 steps)

```bash
# 1. install it (done above if you used ".[mcp]")
pip install -e ".[mcp]"

# 2. link your WhatsApp once — scan the QR it prints
python -m piwapp.mcp_server --pair my.json
#    creates my.json (+ .keys + .db) and prints the exact settings to use next

# 3. register it with your assistant
```

**Claude Code** — one command, no files to edit:

```bash
claude mcp add piwapp \
  -e PIWAPP_AUTH=my.json -e PIWAPP_DB=my.json.db \
  -- python -m piwapp.mcp_server
```

**Claude Desktop / VS Code (Copilot)** — add this to the MCP config
(`claude_desktop_config.json`, or `.vscode/mcp.json` under a `"servers"` key):

```json
{
  "mcpServers": {
    "piwapp": {
      "command": "python",
      "args": ["-m", "piwapp.mcp_server"],
      "env": {
        "PIWAPP_AUTH": "/full/path/my.json",
        "PIWAPP_KEYS": "/full/path/my.json.keys",
        "PIWAPP_DB": "/full/path/my.json.db"
      }
    }
  }
}
```

Then just talk to your assistant:

> *"Send 'on my way' to +15551234567"*
> *"What are my most recent WhatsApp chats?"*
> *"Search my messages for 'invoice'"*
> *"Send this photo to the Family group: ~/Pictures/dog.jpg"*
> *"Watch the Test group and reply to whoever messages me"*

### The tools it exposes

| Tool | What it does |
|---|---|
| `start_pairing` / `pairing_status` | link a device by QR **right inside the chat** |
| `send_message` | send a text (direct or group) |
| `send_file` | send an image/video/audio/document from a path |
| `wait_for_messages` | wait for incoming messages (the "listen" half of a chat) |
| `list_chats` / `get_messages` | browse recent chats and their messages |
| `search_messages` | full-text search your history |
| `last_sent_message` | the last thing you sent |
| `list_groups` / `group_info` | your groups and their details |
| `download_media` | save media from a stored message to a file |
| `connection_status` / `archive_stats` | health + summary |

The archive tools work without a live connection; sending and `wait_for_messages`
need live mode (i.e. `PIWAPP_AUTH` set to a paired account).

> **Note on accounts & privacy.** Your WhatsApp login lives only in *your* `my.json`
> (+ `.keys`/`.db`) — it's never shared or committed. Sharing piwapp means sharing
> the *code*; each person links their own phone. And run only **one** thing at a
> time against a given account file (the CLI, `--pair`, or the MCP server — not
> several at once), since WhatsApp allows a device a single live connection.

See [`USAGE.md`](USAGE.md) for more detail and ready-to-paste configs.

---

## How it works (and how it's different)

WhatsApp Web speaks a custom binary protocol over a WebSocket, wrapped in two
layers of encryption: a **Noise** handshake for the connection, and the **Signal
protocol** (the same one Signal Messenger uses) for end-to-end message encryption.
The Double Ratchet for direct chats and Sender Keys for groups. piwapp implements
**all of that natively in Python**.

That's the differentiator. The other ways to use WhatsApp from Python either drive
a real browser (fragile), wrap a Go library like `whatsmeow` (ships a compiled
binary), or use the paid official Cloud API. piwapp is a **self-contained, pure-Python
stack with no native bridge** — easy to read, audit, and hack on — and it treats
**group chat as a first-class feature**.

<details>
<summary><b>Component status (click to expand)</b></summary>

| Area | Status |
|---|---|
| WebSocket transport + Noise XX handshake | ✅ tested |
| WABinary codec + token tables | ✅ tested |
| Signal: X3DH, Double Ratchet (1:1), Sender Keys (groups) | ✅ tested |
| QR pairing + login + auto-reconnect/keepalive | ✅ live-verified |
| Pre-key upload (enables receiving) | ✅ live-verified |
| Receive & decrypt (direct + group) | ✅ live-verified |
| Send 1:1 (to external contacts) | ✅ live-verified |
| Send to groups (sender-key fan-out, tested to 46 devices) | ✅ live-verified |
| Media send + receive | ✅ live-verified |
| Chat-history sync → SQLite archive | ✅ live-verified (83 chats / 576 msgs) |
| MCP server (read + live send + pairing + listen) | ✅ live-verified |
| Rich group-management APIs (history, join-requests, activity feed) | 🚧 planned |

</details>

---

## Development & tests

```bash
pip install -e ".[dev]"
python -m pytest                 # ~147 tests, all offline
```

The suite covers the binary codec (with property-based fuzzing), the full Noise
handshake, Signal 1:1 and group crypto (including out-of-order and tamper
rejection), a complete mock-server login + reconnect flow, the event/store layers,
end-to-end message encode/decode, media encrypt/upload/download, and the MCP tools.
A gated integration test (`PIWAPP_TEST_REAL=1`) does a real handshake with
`web.whatsapp.com`.

---

## Roadmap

Next up are the **rich group-management APIs** — persistent group state with change
history, batch member management, a join-request approval workflow, and an activity
feed — plus retry receipts and app-state sync. That group tooling is piwapp's
intended headline feature.

## License

MIT
