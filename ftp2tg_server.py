import asyncio
import hmac
import logging
import os
import secrets
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pyftpdlib.authorizers import AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from telethon import TelegramClient, events
from telethon.errors import (
    ChatMigratedError,
    FloodWaitError,
    InputUserDeactivatedError,
    UserIsBlockedError,
)

# --- Configuration (from environment variables) ---
API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
BOT_TOKEN = os.environ["TG_BOT_TOKEN"]
PUBLIC_IP = os.environ["PUBLIC_IP"]
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

DB_PATH = Path(os.environ.get("DB_PATH", "/opt/ftp2tg/ftp2tg.db"))
SESSION_PATH = Path(os.environ.get("SESSION_PATH", "/opt/ftp2tg/bot_session"))
SPOOL_DIR = Path(os.environ.get("SPOOL_DIR", "/var/spool/ftp2tg"))
FTP_PORT = int(os.environ.get("FTP_PORT", "2121"))
PASSIVE_PORT_START = int(os.environ.get("PASSIVE_PORT_START", "60000"))
PASSIVE_PORT_END = int(os.environ.get("PASSIVE_PORT_END", "60050"))

CONCURRENT_UPLOADS = 2
DELAY_BETWEEN_FILES = 1.5
MAX_RETRIES = 3
MAX_FILE_SIZE_BYTES = 2000 * 1024 * 1024  # 2000 MiB Telegram MTProto limit

INCOMING_DIR = SPOOL_DIR / "incoming"
QUEUE_DIR = SPOOL_DIR / "queue"
for d in (INCOMING_DIR, QUEUE_DIR, DB_PATH.parent):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Shared async state between FTP thread and Telethon loop
tg_loop = asyncio.new_event_loop()
wake_event: asyncio.Event | None = None
tg_ready = threading.Event()
in_flight_ids: set[int] = set()


# --- Database Helpers ---
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    return conn


def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS users
               (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                tg_chat_id INTEGER UNIQUE NOT NULL,
                tg_user_id INTEGER,
                group_chats_enabled BOOLEAN CHECK (group_chats_enabled IN (0,1)) DEFAULT 0,
                setting_send_file_name BOOLEAN CHECK (setting_send_file_name IN (0,1)) DEFAULT 0,
                is_stopped BOOLEAN CHECK (is_stopped IN (0,1)) DEFAULT 0,
                tg_migrated_chat_id INTEGER
               );"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS file_send_schedule
               (id INTEGER PRIMARY KEY AUTOINCREMENT,
                time_received timestamp NOT NULL,
                file_path TEXT NOT NULL,
                tg_chat_id INTEGER NOT NULL,
                is_incomplete BOOLEAN CHECK (is_incomplete IN (0,1)),
                time_sent timestamp
               );"""
        )

        # Safe non-destructive migrations for existing databases
        for alter_sql in (
            "ALTER TABLE users ADD COLUMN tg_migrated_chat_id INTEGER;",
            "ALTER TABLE file_send_schedule ADD COLUMN retries INTEGER DEFAULT 0;",
            "ALTER TABLE file_send_schedule ADD COLUMN failed BOOLEAN DEFAULT 0;",
        ):
            try:
                cur.execute(alter_sql)
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Ensure admin row exists if ADMIN_PASSWORD is provided and table has no admin
        if ADMIN_PASSWORD:
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password, tg_chat_id) VALUES ('admin', ?, 39707325)",
                (ADMIN_PASSWORD,),
            )
        conn.commit()
    logging.info("Database initialized at %s", DB_PATH)


def get_user_by_username(username: str):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_chat_id(chat_id: int):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE tg_chat_id = ? OR tg_migrated_chat_id = ?",
            (chat_id, chat_id),
        ).fetchone()


def schedule_file(file_path: str, tg_chat_id: int, is_incomplete: int) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO file_send_schedule
               (time_received, file_path, tg_chat_id, is_incomplete, time_sent, retries, failed)
               VALUES (?, ?, ?, ?, NULL, 0, 0)""",
            (now, file_path, tg_chat_id, is_incomplete),
        )
        conn.commit()
        return cur.lastrowid


def trigger_workers():
    if wake_event is not None:
        tg_loop.call_soon_threadsafe(wake_event.set)


# --- Custom SQLite FTP Authorizer ---
class SQLiteAuthorizer:
    def validate_authentication(self, username, password, handler):
        user = get_user_by_username(username)
        if not user:
            raise AuthenticationFailed("Invalid username or password.")
        if user["is_stopped"]:
            raise AuthenticationFailed("Account is paused. Send /resume in Telegram.")
        if not hmac.compare_digest(str(user["password"]), str(password)):
            raise AuthenticationFailed("Invalid username or password.")

    def get_home_dir(self, username):
        user = get_user_by_username(username)
        user_dir = INCOMING_DIR / str(user["id"])
        user_dir.mkdir(parents=True, exist_ok=True)
        return str(user_dir)

    def has_user(self, username):
        return get_user_by_username(username) is not None

    def has_perm(self, username, perm, path=None):
        # e=cwd, l=list, w=write/upload, m=mkdir (useful for cameras creating date folders)
        return perm in "elwm"

    def get_perms(self, username):
        return "elwm"

    def get_msg_login(self, username):
        return "Connected to Virtual Telegram FTP."

    def get_msg_quit(self, username):
        return "Goodbye."

    def impersonate_user(self, username, password):
        pass

    def terminate_impersonation(self, username):
        pass


# --- Custom FTP Handler ---
class MultiUserTelegramFTPHandler(FTPHandler):
    def _target_chat_id(self):
        user = get_user_by_username(self.username)
        if not user:
            return None
        return user["tg_migrated_chat_id"] or user["tg_chat_id"]

    def on_file_received(self, file_path):
        src = Path(file_path)
        chat_id = self._target_chat_id()
        if chat_id is None:
            src.unlink(missing_ok=True)
            return

        # Move to unique spool folder to preserve exact original filename
        job_dir = QUEUE_DIR / str(uuid.uuid4())
        job_dir.mkdir(parents=True, exist_ok=True)
        dest = job_dir / src.name
        shutil.move(str(src), str(dest))

        row_id = schedule_file(str(dest), chat_id, is_incomplete=0)
        logging.info("[FTP] Queued #%d (%s) for chat %d", row_id, src.name, chat_id)
        trigger_workers()

    def on_incomplete_file_received(self, file_path):
        src = Path(file_path)
        filename = src.name
        chat_id = self._target_chat_id()

        # Remove partial file so disk doesn't fill up, but log it in SQLite
        src.unlink(missing_ok=True)
        if chat_id is not None:
            row_id = schedule_file(filename, chat_id, is_incomplete=1)
            logging.warning(
                "[FTP] Incomplete transfer #%d (%s) for chat %d",
                row_id,
                filename,
                chat_id,
            )
            trigger_workers()


# --- Telethon Upload Worker & Bot Commands ---
def fetch_next_job():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT * FROM file_send_schedule
               WHERE time_sent IS NULL AND COALESCE(failed, 0) = 0
               ORDER BY id ASC LIMIT 20"""
        ).fetchall()
        for row in rows:
            if row["id"] not in in_flight_ids:
                in_flight_ids.add(row["id"])
                return dict(row)
    return None


def mark_sent(row_id: int):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE file_send_schedule SET time_sent = ? WHERE id = ?",
            (now, row_id),
        )
        conn.commit()


def mark_retry_or_fail(row_id: int, retries: int):
    failed = 1 if retries >= MAX_RETRIES else 0
    with get_db() as conn:
        conn.execute(
            "UPDATE file_send_schedule SET retries = ?, failed = ? WHERE id = ?",
            (retries, failed, row_id),
        )
        conn.commit()
    return failed == 1


def cleanup_queued_file(file_path_str: str):
    p = Path(file_path_str)
    if p.exists():
        p.unlink(missing_ok=True)
    # Remove the UUID parent directory if it's inside QUEUE_DIR
    if p.parent.parent == QUEUE_DIR:
        shutil.rmtree(p.parent, ignore_errors=True)


async def process_job(worker_id: int, client: TelegramClient, job: dict):
    row_id = job["id"]
    chat_id = job["tg_chat_id"]
    user = get_user_by_chat_id(chat_id)
    target_chat = (
        (user["tg_migrated_chat_id"] or user["tg_chat_id"]) if user else chat_id
    )

    try:
        # Case 1: Incomplete FTP upload -> notify user and mark handled
        if job["is_incomplete"]:
            filename = Path(job["file_path"]).name
            await client.send_message(
                target_chat,
                f"⚠️ Incomplete FTP upload detected: `{filename}`.\n"
                "The transfer dropped before finishing and was not saved. Please re-upload.",
            )
            mark_sent(row_id)
            logging.info("[Worker %d] Notified chat %d of incomplete file %s", worker_id, target_chat, filename)
            return

        # Case 2: Normal file upload
        file_path = Path(job["file_path"])
        if not file_path.exists():
            logging.warning("[Worker %d] Missing file for job #%d: %s", worker_id, row_id, file_path)
            mark_retry_or_fail(row_id, MAX_RETRIES)
            return

        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            size_gb = file_size / (1024 ** 3)
            await client.send_message(
                target_chat,
                f"❌ `{file_path.name}` ({size_gb:.2f} GB) exceeds Telegram's 2 GB file limit and could not be sent.",
            )
            mark_retry_or_fail(row_id, MAX_RETRIES)
            cleanup_queued_file(str(file_path))
            return

        send_name = bool(user["setting_send_file_name"]) if user else False
        caption = file_path.name if send_name else ""

        logging.info(
            "[Worker %d] Uploading #%d: %s (%.1f MB) -> %d",
            worker_id,
            row_id,
            file_path.name,
            file_size / (1024 * 1024),
            target_chat,
        )
        await client.send_file(
            target_chat,
            str(file_path),
            caption=caption,
            force_document=True,
        )
        mark_sent(row_id)
        cleanup_queued_file(str(file_path))
        logging.info("[Worker %d] Sent #%d: %s", worker_id, row_id, file_path.name)

    except ChatMigratedError as e:
        new_id = e.new_chat_id
        logging.info("[Worker %d] Chat %d migrated to %d", worker_id, target_chat, new_id)
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET tg_migrated_chat_id = ? WHERE tg_chat_id = ?",
                (new_id, chat_id),
            )
            conn.execute(
                "UPDATE file_send_schedule SET tg_chat_id = ? WHERE id = ?",
                (new_id, row_id),
            )
            conn.commit()
        trigger_workers()

    except (UserIsBlockedError, InputUserDeactivatedError):
        logging.warning("[Worker %d] User %d blocked bot; marking is_stopped=1", worker_id, target_chat)
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET is_stopped = 1 WHERE tg_chat_id = ? OR tg_migrated_chat_id = ?",
                (target_chat, target_chat),
            )
            conn.commit()
        mark_retry_or_fail(row_id, MAX_RETRIES)
        if not job["is_incomplete"]:
            cleanup_queued_file(job["file_path"])

    except FloodWaitError as e:
        wait_sec = e.seconds + 2
        logging.warning("[Worker %d] FloodWait: sleeping %ds", worker_id, wait_sec)
        await asyncio.sleep(wait_sec)
        trigger_workers()

    except Exception as e:
        retries = (job.get("retries") or 0) + 1
        permanently_failed = mark_retry_or_fail(row_id, retries)
        logging.error(
            "[Worker %d] Error on #%d (attempt %d/%d): %s",
            worker_id,
            row_id,
            retries,
            MAX_RETRIES,
            e,
        )
        if permanently_failed and not job["is_incomplete"]:
            cleanup_queued_file(job["file_path"])
        await asyncio.sleep(5 * retries)
        trigger_workers()

    finally:
        in_flight_ids.discard(row_id)


async def worker_loop(worker_id: int, client: TelegramClient):
    while True:
        job = fetch_next_job()
        if job is None:
            wake_event.clear()
            try:
                await asyncio.wait_for(wake_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            continue

        await process_job(worker_id, client, job)
        await asyncio.sleep(DELAY_BETWEEN_FILES)


def format_account_details(username: str) -> str:
    return (
        f"FTP Server:   `{PUBLIC_IP}`\n"
        f"Port:               `{FTP_PORT}`\n"
        f"Username:    `{username}`\n"
        f"Password:     _(the one you provided)_\n"
        f"Upload\n"
        f"Directory:      `/` or any"
    )


def register_bot_commands(client: TelegramClient):
    @client.on(events.NewMessage(pattern=r"^/start$"))
    async def cmd_start(event):
        await event.respond(
            "Use /create command to create an FTP account\n"
            "Use /password command to change FTP account password\n"
            "Use /account command to see FTP account details\n\n"
            "Other commands: /status | /filename | /stop | /resume"
        )

    @client.on(events.NewMessage(pattern=r"^/create$"))
    async def cmd_create(event):
        chat_id = event.chat_id
        if get_user_by_chat_id(chat_id):
            await event.respond(
                "You already have an FTP account. Use /account to view details or /password to change your password."
            )
            return

        sender = await event.get_sender()
        tg_user_id = sender.id if sender else None

        try:
            async with client.conversation(chat_id, timeout=120) as conv:
                await conv.send_message("Send the **username** you want to use:")
                u_msg = await conv.get_response()
                username = u_msg.raw_text.strip()

                if not username or " " in username:
                    await conv.send_message("Invalid username (no spaces allowed). Run /create to try again.")
                    return
                if get_user_by_username(username):
                    await conv.send_message("That username is already taken. Run /create to try another.")
                    return

                await conv.send_message("Send the **password** for your FTP account:")
                p_msg = await conv.get_response()
                password = p_msg.raw_text.strip()

                if not password:
                    await conv.send_message("Password cannot be empty. Run /create to try again.")
                    return

                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO users (username, password, tg_chat_id, tg_user_id)
                           VALUES (?, ?, ?, ?)""",
                        (username, encode_password(password), chat_id, tg_user_id),
                    )
                    conn.commit()

                await conv.send_message(
                    f"FTP account created!\n\n{format_account_details(username)}"
                )
        except asyncio.TimeoutError:
            await event.respond("Timed out. Send /create whenever you're ready to try again.")

    @client.on(events.NewMessage(pattern=r"^/password$"))
    async def cmd_password(event):
        chat_id = event.chat_id
        user = get_user_by_chat_id(chat_id)
        if not user:
            await event.respond("You don't have an FTP account yet. Use /create first.")
            return

        try:
            async with client.conversation(chat_id, timeout=120) as conv:
                await conv.send_message("Send your **new password**:")
                p_msg = await conv.get_response()
                new_password = p_msg.raw_text.strip()

                if not new_password:
                    await conv.send_message("Password cannot be empty. Run /password to try again.")
                    return

                with get_db() as conn:
                    conn.execute(
                        "UPDATE users SET password = ? WHERE id = ?",
                        (encode_password(new_password), user["id"]),
                    )
                    conn.commit()

                await conv.send_message("FTP password updated successfully.")
        except asyncio.TimeoutError:
            await event.respond("Timed out. Send /password to try again.")

    @client.on(events.NewMessage(pattern=r"^/account$"))
    async def cmd_account(event):
        user = get_user_by_chat_id(event.chat_id)
        if not user:
            await event.respond("You don't have an FTP account yet. Use /create first.")
            return
        await event.respond(format_account_details(user["username"]))

    @client.on(events.NewMessage(pattern=r"^/filename$"))
    async def cmd_filename(event):
        user = get_user_by_chat_id(event.chat_id)
        if not user:
            await event.respond("Use /create first.")
            return
        new_val = 0 if user["setting_send_file_name"] else 1
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET setting_send_file_name = ? WHERE id = ?",
                (new_val, user["id"]),
            )
            conn.commit()
        await event.respond(f"Send filename as caption: **{'ON' if new_val else 'OFF'}**")

    @client.on(events.NewMessage(pattern=r"^/(stop|resume)$"))
    async def cmd_stop_resume(event):
        user = get_user_by_chat_id(event.chat_id)
        if not user:
            await event.respond("Use /create first.")
            return
        stopped = 1 if event.pattern_match.group(1) == "stop" else 0
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET is_stopped = ? WHERE id = ?", (stopped, user["id"])
            )
            conn.commit()
        await event.respond("FTP uploads **paused**." if stopped else "FTP uploads **resumed**.")

    @client.on(events.NewMessage(pattern=r"^/status$"))
    async def cmd_status(event):
        user = get_user_by_chat_id(event.chat_id)
        if not user:
            await event.respond("Use /create first.")
            return
        target_chat = user["tg_migrated_chat_id"] or user["tg_chat_id"]
        with get_db() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM file_send_schedule WHERE tg_chat_id = ? AND time_sent IS NULL AND COALESCE(failed, 0) = 0",
                (target_chat,),
            ).fetchone()[0]
        await event.respond(
            f"**Status**\n"
            f"Username: `{user['username']}`\n"
            f"Active: {'No (Paused)' if user['is_stopped'] else 'Yes'}\n"
            f"Send filename caption: {'ON' if user['setting_send_file_name'] else 'OFF'}\n"
            f"Queued files: `{pending}`"
        )

async def start_telethon():
    global wake_event
    wake_event = asyncio.Event()

    client = TelegramClient(str(SESSION_PATH), API_ID, API_HASH)
    await client.start(bot_token=BOT_TOKEN)
    register_bot_commands(client)

    logging.info("[Telegram] Connected via MTProto (2 GB upload limit active).")
    workers = [
        asyncio.create_task(worker_loop(i + 1, client))
        for i in range(CONCURRENT_UPLOADS)
    ]
    tg_ready.set()
    trigger_workers()  # Pick up any unsent rows from previous runs
    await asyncio.gather(*workers, client.run_until_disconnected())


def run_telethon_thread():
    asyncio.set_event_loop(tg_loop)
    tg_loop.run_until_complete(start_telethon())


def main():
    init_db()

    t = threading.Thread(target=run_telethon_thread, daemon=True)
    t.start()
    tg_ready.wait()

    handler = MultiUserTelegramFTPHandler
    handler.authorizer = SQLiteAuthorizer()
    handler.masquerade_address = PUBLIC_IP
    handler.passive_ports = range(PASSIVE_PORT_START, PASSIVE_PORT_END + 1)

    server = FTPServer(("0.0.0.0", FTP_PORT), handler)
    server.max_cons = 100
    server.max_cons_per_ip = 10
    logging.info("[FTP] Multi-user server listening on %s:%d", PUBLIC_IP, FTP_PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()

