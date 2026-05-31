# Using piwapp

A practical guide to what piwapp can do today: pair to WhatsApp, stay online,
receive messages, and send 1:1 text — all in pure Python.

> Requires **Python 3.12+**. Install with `pip install piwapp`
> (or `pip install "piwapp[mcp]"` for the MCP server).

---

## 1. Quick start — the CLI

Installing piwapp adds a `piwapp` command (equivalent to `python -m piwapp`):

```bash
piwapp                           # uses ./piwapp_auth.json (created on first run)
# or a custom auth file:
piwapp my_account.json
```

What happens:

1. **First run** prints a QR (in the terminal *and* as `piwapp_qr.png`). Scan it
   with **WhatsApp → Linked Devices → Link a Device**.
2. It pairs, reconnects, logs in, uploads pre-keys, and prints
   `✓ Online as <your-jid>` — then **stays connected**.
3. **Incoming messages** print as `💬 [sender] text`.
4. **Later runs** reuse the saved session (`my_account.json` + `my_account.json.keys`)
   and go straight to Online — **no QR**.

Set `PIWAPP_DEBUG=1` to see every protocol frame (useful for debugging).

---

## 2. Programmatic use

### Connect and stay online

```python
import asyncio
from pathlib import Path
from piwapp import Client, ConnectionConfig, AuthenticationCreds

auth = Path("my_account.json")

def load_creds() -> AuthenticationCreds:
    if auth.exists():
        return AuthenticationCreds.from_json(auth.read_text())
    creds = AuthenticationCreds.initial()
    auth.write_text(creds.to_json())
    return creds

async def main():
    creds = load_creds()
    client = Client(
        creds,
        ConnectionConfig(),
        on_creds_update=lambda c: auth.write_text(c.to_json()),  # persist creds
        keys_path=str(auth) + ".keys",                           # persist Signal keys
    )

    # --- subscribe to events ---
    client.on("connection.update", on_connection)        # lifecycle + QR
    client.events.on(WAEventType.MESSAGES_UPSERT, on_msg)  # incoming messages

    await client.start()        # runs the connect/reconnect loop until stopped

asyncio.run(main())
```

### Handle the QR / connection lifecycle

`connection.update` payloads are dicts:

```python
from piwapp.auth.qr import save_qr_png

async def on_connection(update: dict):
    if "qr" in update:
        save_qr_png(update["qr"], "login.png")   # render a scannable PNG
        print("scan login.png")
    if update.get("connection") == "open":
        print("online as", (update.get("me") or {}).get("id"))
    if update.get("connection") == "close" and update.get("logged_out"):
        print("logged out:", update.get("reason"))
```

### Receive messages

```python
from piwapp.events import WAEventType
from piwapp.api.messages import text_of

def on_msg(payload):                 # payload is a MessagesUpsert
    for m in payload.messages:
        jid  = m["key"]["remoteJid"]            # chat the message is in
        who  = m["key"].get("participant") or jid
        text = m.get("text")                    # decoded text, or None for non-text
        print(f"from {who}: {text!r}")
```

Each message dict has: `key` (`remoteJid`, `id`, `fromMe`, `participant`),
`message` (the decoded WAProto `Message`), `text`, `messageTimestamp`, `pushName`.
Decryption failures surface as a `MESSAGES_UPDATE` event with a `decryptError`.

### Send a text (1:1 or group)

```python
# once client.is_open is True:
await client.send_text("15551234567@s.whatsapp.net", "hello from piwapp 🐍")

# groups: send_text auto-detects @g.us, or call send_group_text directly
await client.send_text("120363xxxxxxxxxxxx@g.us", "hello group")

# list the groups you're in (returns [{id, subject, addressing_mode, size}, ...])
groups = await client.fetch_groups()
```

`send_text` does the full flow for you: USync device discovery, pre-key fetch +
session setup, per-device fan-out encryption, and the stanza assembly. For
groups it additionally creates your sender key, distributes the sender-key
message to every member device, and encrypts the body once (`skmsg`).

### Send media (image / video / audio / document)

```python
# from a file path (MIME + media type inferred from the extension):
await client.send_file("…@s.whatsapp.net", "photo.jpg", caption="hi 🐍")

# or from bytes you already have:
await client.send_media("…@g.us", img_bytes, mimetype="image/jpeg",
                        caption="for the group", width=1280, height=720)
```

`send_media` encrypts the file (AES-CBC + HMAC), fetches upload hosts/token via a
`media_conn` query, uploads to WhatsApp's media server, builds the media proto
(url/directPath/mediaKey/hashes), and relays it 1:1 or to a group — same fan-out
as text. Works for `@s.whatsapp.net` and `@g.us`.

### Receive / download media

Incoming media messages carry a `media` summary in the message dict
(`{type, mimetype, fileName, fileLength, caption}`); the caption also surfaces as
`text`. Download + decrypt the bytes with the client (no socket needed — it's a
plain authenticated HTTPS fetch):

```python
def on_msg(payload):
    for m in payload.messages:
        if m.get("media"):
            print("media:", m["media"])           # type/mimetype/size/caption

# later, with the decoded Message proto:
data = await client.download_media(m["message"])  # decrypted bytes, hashes verified
open("out.jpg", "wb").write(data)
```

### Querying state

A bound in-memory store accumulates what flows through:

```python
client.store.messages          # {chat_jid: {msg_id: message_dict}}
client.store.chats             # {jid: chat_dict}
client.store.contacts          # {jid: contact_dict}
client.store.get_chat_messages("15551234567@s.whatsapp.net")
```

---

## 3. JIDs (addresses)

- **User:** `<phone>@s.whatsapp.net` (e.g. `447000000000@s.whatsapp.net`)
- **Group:** `<id>@g.us`
- A specific device: `<phone>:<device>@s.whatsapp.net`

Use the `JID` helper for parsing:

```python
from piwapp import JID
j = JID.parse("447000000000@s.whatsapp.net")
j.is_user, j.is_group, j.user, j.server
```

---

## 4. Files piwapp writes

| File | Contents |
|---|---|
| `<auth>.json` | Long-lived credentials (identity, noise key, registration, `me`) |
| `<auth>.json.keys` | Signal sessions, pre-keys, sender-keys (atomic writes) |
| `<auth>.json.rejected` | A previous session that the server rejected (kept, not deleted) |
| `piwapp_qr.png` | The current login QR image (CLI) |

Keep these private — they are your device's login.

---

## 5. What works today / what's next

**Working (live-verified):** QR pairing, stable login + auto-reconnect, pre-key
upload, **inbound message decryption**, **1:1 outbound send**, **group send**
(sender-key distribution), group listing, **history sync** (past chats/messages
on a fresh login, incl. your own sent messages), key persistence across restarts.

**In progress / planned:** media (images/docs), app-state collections
(mute/pin/contact-list + LID→name display), the rich group-management APIs
(metadata, activity feed, join-request workflow).

### Reading history

On a freshly-paired device, WhatsApp pushes a history bootstrap. Subscribe to it:

```python
from piwapp.events import WAEventType

def on_history(data):           # {chats, contacts, messages, syncType, progress}
    print(f"got {len(data['messages'])} historical messages")

client.events.on(WAEventType.MESSAGING_HISTORY_SET, on_history)
```

Historical messages also flow through `messages.upsert` (type `append`) and into
`client.store`, so `client.store.get_chat_messages(jid)` includes them.

### Persisting to disk (SQLite)

By default the store is in-memory (lost on exit). Pass `db_path` to persist
messages/chats/contacts to SQLite so history survives restarts:

```python
client = Client(creds, ConnectionConfig(),
                on_creds_update=save, keys_path="acct.json.keys",
                db_path="acct.db")     # durable archive
```

Then query it — even **offline**, without connecting:

```python
from piwapp.store import SqliteStore
db = SqliteStore("acct.db")
db.last_sent_message()                 # who/what you wrote last
db.get_chat_messages("…@g.us", 50)     # recent messages in a chat
db.recent_chats(20)
db.search_text("weather")
```

Or use the CLI helper: `python scripts/query.py acct.db` (summary),
`… acct.db chat <jid> 20`, `… acct.db search <text>`.

> The `.db` files contain your message content — they're git-ignored by default.

---

## 5b. MCP server — give an LLM access to WhatsApp

`piwapp` ships an [MCP](https://modelcontextprotocol.io) server so an LLM (Claude
Desktop, Claude Code, any MCP client) can query your chat archive and — in live
mode — send messages.

Install the extra: `pip install "piwapp[mcp]"` (adds the `piwapp-mcp` command).

**Two tiers of tools:**

| Tool | Tier | What it does |
|---|---|---|
| `list_chats` | archive | recent chats (groups + 1:1) |
| `get_messages` | archive | messages in a chat |
| `search_messages` | archive | full-text search |
| `last_sent_message` | archive | the last thing you sent |
| `group_info` | archive | stored group metadata |
| `archive_stats` | archive | counts + connection status |
| `send_message` | **live** | send a text (1:1 or group) |
| `send_file` | **live** | send a local file (image/video/audio/document) |
| `wait_for_messages` | **live** | block until incoming message(s) arrive |
| `download_media` | archive | decrypt media from a stored message to a file |
| `list_groups` | **live** | groups you're in (live query) |
| `connection_status` | **live** | is the socket online |

**Hold a conversation from your LLM.** With live mode on, an agent can run a
chat loop entirely through MCP: call `wait_for_messages` (optionally filtered to
one `chat_jid`) to listen, read the decoded text, then reply with `send_message`
or `send_file`, and repeat. Group messages decrypt automatically — each
participant's sender key is installed the first time they post.

Archive tools need only the SQLite DB — **no connection**. Live tools activate
when `PIWAPP_AUTH` points at an already-paired creds file; the server then keeps a
background connection online using its **own dedicated device** (pair a separate
one so it never collides with your other sessions).

**Run it** (stdio transport):

```bash
# read-only over the archive
PIWAPP_DB=piwapp_capture.json.db piwapp-mcp

# live (send + read), with a dedicated paired device
PIWAPP_AUTH=piwapp_mcp.json PIWAPP_DB=piwapp_mcp.json.db piwapp-mcp
```

**Wire into Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "piwapp": {
      "command": "piwapp-mcp",
      "env": {
        "PIWAPP_DB": "/full/path/piwapp_capture.json.db"
      }
    }
  }
}
```

Add `"PIWAPP_AUTH": "/full/path/piwapp_mcp.json"` to that `env` block to enable sending.

**Or via Claude Code CLI:**

```bash
claude mcp add piwapp \
  -e PIWAPP_DB=/full/path/piwapp_capture.json.db \
  -- piwapp-mcp
```

> `send_message` accepts a full JID or a
> bare phone number (treated as a 1:1 chat). The raw message protobuf is never
> exposed through MCP — only decoded text + metadata.

---

## 6. Tips & gotchas

- **One connection per credential.** Don't run two clients with the same auth
  file at once — WhatsApp will bump one with a `conflict`.
- **Each pairing uses a Linked-Devices slot.** Unlink stale "Chrome" devices
  from your phone (WhatsApp → Linked Devices) to tidy up.
- **A rejected saved session** (reason 401) is moved to `<auth>.json.rejected`;
  re-run to pair fresh.
- **Console encoding:** piwapp forces UTF-8 stdout so emoji/arrows don't crash on
  legacy Windows code pages.
