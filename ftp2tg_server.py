#!/usr/bin/env python3
"""Virtual Multi-User FTP to Telegram Server (MTProto / 2 GB limit)."""

import asyncio
import logging
import os
import re
import sqlite3
import threading
from pathlib import Path

from pyftpdlib.authorizers import AuthenticationFailed, DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from telethon import TelegramClient, events, utils
from telethon.errors import ChatWriteForbiddenError, FloodWaitError
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.types import MessageActionChannelMigrateFrom, PeerChat

# ---------------------------------------------------------------------------
# Logging & Environment Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ftp2tg")

BASE_DIR = Path(__file__).resolve().parent


def load_env(env_path: Path) -> None:
    """Load key=value pairs from .env without requiring python-dotenv."""
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_env(BASE_DIR / ".env")


def env_any(*keys: str, default: str = "") -> str:
    for key in keys:
        val = os.getenv(key)
        if val:
            return val
    return default


API_ID = int(env_any("API_ID", "TG_API_ID", default="0"))
API_HASH = env_any("API_HASH", "TG_API_HASH")
BOT_TOKEN = env_any("BOT_TOKEN", "TG_BOT_TOKEN")

DB_PATH = env_any("DB_PATH", default="/home/opc/main.db")
SPOOL_DIR = Path(env_any("SPOOL_DIR", default=str(BASE_DIR / "spool")))
SESSION_PATH = env_any("SESSION_PATH", default=str(BASE_DIR / "ftp2tg_bot"))

FTP_HOST = env_any("FTP_HOST", default="0.0.0.0")
FTP_PORT = int(env_any("FTP_PORT", default="21"))
PUBLIC_IP = env_any("PUBLIC_IP", "FTP_PUBLIC_IP", default="")
PASSIVE_START = int(env_any("PASSIVE_PORT_START", default="60000"))
PASSIVE_END = int(env_any("PASSIVE_PORT_END", default="60050"))

SPOOL_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# SQLite Database (WAL Mode)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tg_chat_id INTEGER UNIQUE NOT NULL,
                tg_migrated_chat_id INTEGER,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                send_filename INTEGER DEFAULT 1,
                stopped INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_send_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tg_chat_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                send_filename INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Ensure optional columns exist on older databases
        cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "tg_migrated_chat_id" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN tg_migrated_chat_id INTEGER")
        if "send_filename" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN send_filename INTEGER DEFAULT 1")
        if "stopped" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN stopped INTEGER DEFAULT 0")
        conn.commit()
    logger.info("Database initialized at %s", DB_PATH)


def safe_user_dir(username: str) -> Path:
    """Return an isolated per-user directory inside SPOOL_DIR."""
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", username)
    user_dir = (SPOOL_DIR / safe_name).resolve()
    if SPOOL_DIR.resolve() not in user_dir.parents:
        raise ValueError("Invalid username path")
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


# ---------------------------------------------------------------------------
# FTP Server (pyftpdlib)
# ---------------------------------------------------------------------------
class SQLiteAuthorizer(DummyAuthorizer):
    """Authenticates FTP users against SQLite and jails each to their own folder."""

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()

    def validate_authentication(self, username, password, handler):
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not user or user["password"] != password:
            raise AuthenticationFailed("Invalid username or password.")

        home_dir = str(safe_user_dir(username))
        with self._lock:
            self.user_table[username] = {
                "pwd": password,
                "home": home_dir,
                "perm": "elradfmwMT",
                "operms": {},
                "msg_login": "Login successful.",
                "msg_quit": "Goodbye.",
            }

    def has_user(self, username):
        if username in self.user_table:
            return True
        with get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row is not None


class TelegramFTPHandler(FTPHandler):
    """Queues every completed FTP upload for the Telethon upload worker."""

    def on_file_received(self, file: str):
        username = self.username
        file_path = Path(file)
        filename = file_path.name

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if not user:
                logger.warning("[FTP] Upload from unknown user '%s', deleting %s", username, file)
                file_path.unlink(missing_ok=True)
                return

            if user["stopped"]:
                logger.info("[FTP] Delivery paused for '%s'; dropping %s", username, filename)
                file_path.unlink(missing_ok=True)
                return

            target_chat = user["tg_migrated_chat_id"] or user["tg_chat_id"]
            send_filename = user["send_filename"]

            conn.execute(
                """
                INSERT INTO file_send_schedule (tg_chat_id, file_path, filename, send_filename)
                VALUES (?, ?, ?, ?)
                """,
                (target_chat, str(file_path), filename, send_filename),
            )
            conn.commit()

        logger.info("[FTP] Queued '%s' from '%s' -> chat %s", filename, username, target_chat)


def start_ftp_server() -> None:
    authorizer = SQLiteAuthorizer()
    handler = TelegramFTPHandler
    handler.authorizer = authorizer
    if PUBLIC_IP:
        handler.masquerade_address = PUBLIC_IP
    handler.passive_ports = range(PASSIVE_START, PASSIVE_END + 1)

    server = FTPServer((FTP_HOST, FTP_PORT), handler)
    server.max_cons = 128
    server.max_cons_per_ip = 16

    display_ip = PUBLIC_IP or FTP_HOST
    logger.info("[FTP] Multi-user server listening on %s:%s", display_ip, FTP_PORT)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Telegram Auto-Migration & Lookup Helpers
# ---------------------------------------------------------------------------
async def get_user_for_chat(client: TelegramClient, chat_id: int):
    """Find user by tg_chat_id or tg_migrated_chat_id; auto-link supergroups."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE tg_chat_id = ? OR tg_migrated_chat_id = ?",
            (chat_id, chat_id),
        ).fetchone()
        if row:
            return row

    if str(chat_id).startswith("-100"):
        try:
            full = await client(GetFullChannelRequest(chat_id))
            old_raw_id = getattr(full.full_chat, "migrated_from_chat_id", None)
            if old_raw_id:
                old_chat_id = utils.get_peer_id(PeerChat(old_raw_id))
                with get_db() as conn:
                    row = conn.execute(
                        "SELECT * FROM users WHERE tg_chat_id = ?",
                        (old_chat_id,),
                    ).fetchone()
                    if row:
                        conn.execute(
                            "UPDATE users SET tg_migrated_chat_id = ? WHERE tg_chat_id = ?",
                            (chat_id, old_chat_id),
                        )
                        conn.execute(
                            "UPDATE file_send_schedule SET tg_chat_id = ? WHERE tg_chat_id = ?",
                            (chat_id, old_chat_id),
                        )
                        conn.commit()
                        logger.info("[Migration] Auto-linked %s -> %s", old_chat_id, chat_id)
                        return conn.execute(
                            "SELECT * FROM users WHERE tg_migrated_chat_id = ?",
                            (chat_id,),
                        ).fetchone()
        except Exception as e:
            logger.warning("[Migration] Could not inspect supergroup %s: %s", chat_id, e)

    return None


# ---------------------------------------------------------------------------
# Telegram Upload Worker
# ---------------------------------------------------------------------------
async def upload_worker(client: TelegramClient) -> None:
    """Continuously sends queued FTP files to Telegram via MTProto."""
    while True:
        try:
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT * FROM file_send_schedule ORDER BY id ASC LIMIT 10"
                ).fetchall()

            if not rows:
                await asyncio.sleep(1.5)
                continue

            for row in rows:
                row_id = row["id"]
                target_chat = row["tg_chat_id"]
                file_path = Path(row["file_path"])
                filename = row["filename"]
                caption = filename if row["send_filename"] else ""

                if not file_path.exists():
                    with get_db() as conn:
                        conn.execute("DELETE FROM file_send_schedule WHERE id = ?", (row_id,))
                        conn.commit()
                    continue

                try:
                    await client.send_file(
                        target_chat,
                        file=str(file_path),
                        caption=caption,
                    )
                    file_path.unlink(missing_ok=True)
                    with get_db() as conn:
                        conn.execute("DELETE FROM file_send_schedule WHERE id = ?", (row_id,))
                        conn.commit()
                    logger.info("[Telegram] Sent '%s' -> chat %s", filename, target_chat)

                except FloodWaitError as e:
                    logger.warning("[Telegram] FloodWait: sleeping %ss", e.seconds)
                    await asyncio.sleep(e.seconds + 1)

                except ChatWriteForbiddenError:
                    entity = await client.get_entity(target_chat)
                    migrated_to = getattr(entity, "migrated_to", None)
                    if migrated_to:
                        new_chat_id = utils.get_peer_id(migrated_to)
                        with get_db() as conn:
                            conn.execute(
                                "UPDATE users SET tg_migrated_chat_id = ? WHERE tg_chat_id = ?",
                                (new_chat_id, target_chat),
                            )
                            conn.execute(
                                "UPDATE file_send_schedule SET tg_chat_id = ? WHERE tg_chat_id = ?",
                                (new_chat_id, target_chat),
                            )
                            conn.commit()
                        logger.info("[Migration] Updated target %s -> %s", target_chat, new_chat_id)
                        continue
                    logger.error("[Telegram] No write permission in chat %s", target_chat)
                    await asyncio.sleep(5)

                except Exception as e:
                    logger.error("[Telegram] Failed sending '%s' to %s: %s", filename, target_chat, e)
                    await asyncio.sleep(5)

        except Exception as e:
            logger.error("[Worker] Unexpected loop error: %s", e)
            await asyncio.sleep(3)


# ---------------------------------------------------------------------------
# Telegram Bot Command Handlers
# ---------------------------------------------------------------------------
def register_bot_commands(client: TelegramClient, bot_username: str | None = None) -> None:
    bot_tag = rf"(?:@{re.escape(bot_username)})?" if bot_username else ""

    @client.on(events.NewMessage())
    async def on_group_migrated(event):
        action = getattr(event.message, "action", None)
        if isinstance(action, MessageActionChannelMigrateFrom):
            old_chat_id = utils.get_peer_id(PeerChat(action.chat_id))
            new_chat_id = event.chat_id
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET tg_migrated_chat_id = ? WHERE tg_chat_id = ?",
                    (new_chat_id, old_chat_id),
                )
                conn.execute(
                    "UPDATE file_send_schedule SET tg_chat_id = ? WHERE tg_chat_id = ?",
                    (new_chat_id, old_chat_id),
                )
                conn.commit()
            logger.info("[Migration] Real-time link %s -> %s", old_chat_id, new_chat_id)

    @client.on(events.NewMessage(pattern=rf"(?i)^/start{bot_tag}$"))
    async def cmd_start(event):
        await event.reply(
            "**FTP to Telegram Bot**\n\n"
            "Commands:\n"
            "• `/create <username> <password>` — Create an FTP account for this chat\n"
            "• `/account` — Show your FTP connection details\n"
            "• `/password <new_password>` — Change your FTP password\n"
            "• `/filename` — Toggle filename captions on/off\n"
            "• `/stop` / `/resume` — Pause or resume forwarding\n"
            "• `/status` — Show account & queue status"
        )

    @client.on(events.NewMessage(pattern=rf"(?i)^/create{bot_tag}(?:\s+(\S+)\s+(\S+))?$"))
    async def cmd_create(event):
        existing = await get_user_for_chat(client, event.chat_id)
        if existing:
            await event.reply(
                f"This chat already has an FTP account (`{existing['username']}`). "
                "Use `/account` to view it or `/password <new_password>` to change the password."
            )
            return

        username = event.pattern_match.group(1)
        password = event.pattern_match.group(2)
        if not username or not password:
            await event.reply("Usage: `/create <username> <password>`")
            return

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (tg_chat_id, username, password) VALUES (?, ?, ?)",
                    (event.chat_id, username, password),
                )
                conn.commit()
            safe_user_dir(username)
        except sqlite3.IntegrityError:
            await event.reply(f"Username `{username}` is already taken. Choose another.")
            return

        host = PUBLIC_IP or FTP_HOST
        await event.reply(
            f"FTP account created:\n"
            f"• **Host:** `{host}`\n"
            f"• **Port:** `{FTP_PORT}`\n"
            f"• **Username:** `{username}`\n"
            f"• **Password:** `{password}`\n"
            f"• **Mode:** Passive (PASV)"
        )

    @client.on(events.NewMessage(pattern=rf"(?i)^/account{bot_tag}$"))
    async def cmd_account(event):
        user = await get_user_for_chat(client, event.chat_id)
        if not user:
            await event.reply("No FTP account found for this chat. Use `/create <username> <password>`.")
            return

        host = PUBLIC_IP or FTP_HOST
        await event.reply(
            f"**FTP Account Details**\n"
            f"• **Host:** `{host}`\n"
            f"• **Port:** `{FTP_PORT}`\n"
            f"• **Username:** `{user['username']}`\n"
            f"• **Password:** `{user['password']}`\n"
            f"• **Filename caption:** `{'ON' if user['send_filename'] else 'OFF'}`\n"
            f"• **Delivery:** `{'PAUSED' if user['stopped'] else 'ACTIVE'}`"
        )

    @client.on(events.NewMessage(pattern=rf"(?i)^/password{bot_tag}(?:\s+(\S+))?$"))
    async def cmd_password(event):
        user = await get_user_for_chat(client, event.chat_id)
        if not user:
            await event.reply("No FTP account found for this chat.")
            return

        new_pw = event.pattern_match.group(1)
        if not new_pw:
            await event.reply("Usage: `/password <new_password>`")
            return

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (new_pw, user["id"]),
            )
            conn.commit()
        await event.reply(f"Password updated for `{user['username']}`.")

    @client.on(events.NewMessage(pattern=rf"(?i)^/filename{bot_tag}$"))
    async def cmd_filename(event):
        user = await get_user_for_chat(client, event.chat_id)
        if not user:
            await event.reply("No FTP account found for this chat.")
            return

        new_val = 0 if user["send_filename"] else 1
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET send_filename = ? WHERE id = ?",
                (new_val, user["id"]),
            )
            conn.commit()
        await event.reply(f"Filename captions are now **{'ON' if new_val else 'OFF'}**.")

    @client.on(events.NewMessage(pattern=rf"(?i)^/(stop|resume){bot_tag}$"))
    async def cmd_stop_resume(event):
        user = await get_user_for_chat(client, event.chat_id)
        if not user:
            await event.reply("No FTP account found for this chat.")
            return

        action = event.pattern_match.group(1).lower()
        stopped = 1 if action == "stop" else 0
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET stopped = ? WHERE id = ?",
                (stopped, user["id"]),
            )
            conn.commit()
        await event.reply("FTP forwarding **paused**." if stopped else "FTP forwarding **resumed**.")

    @client.on(events.NewMessage(pattern=rf"(?i)^/status{bot_tag}$"))
    async def cmd_status(event):
        user = await get_user_for_chat(client, event.chat_id)
        if not user:
            await event.reply("No FTP account found for this chat.")
            return

        target_chat = user["tg_migrated_chat_id"] or user["tg_chat_id"]
        with get_db() as conn:
            queued = conn.execute(
                "SELECT COUNT(*) FROM file_send_schedule WHERE tg_chat_id = ?",
                (target_chat,),
            ).fetchone()[0]

        await event.reply(
            f"**Status for `{user['username']}`**\n"
            f"• **Delivery:** `{'PAUSED' if user['stopped'] else 'ACTIVE'}`\n"
            f"• **Queued files:** `{queued}`"
        )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
async def main() -> None:
    if not (API_ID and API_HASH and BOT_TOKEN):
        raise RuntimeError("Missing API_ID, API_HASH, or BOT_TOKEN in .env")

    init_db()

    client = TelegramClient(SESSION_PATH, API_ID, API_HASH)
    await client.start(bot_token=BOT_TOKEN)
    me = await client.get_me()
    logger.info("[Telegram] Connected via MTProto as @%s (2 GB upload limit active).", me.username)

    register_bot_commands(client, me.username)

    ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
    ftp_thread.start()

    worker_task = asyncio.create_task(upload_worker(client))
    try:
        await client.run_until_disconnected()
    finally:
        worker_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
