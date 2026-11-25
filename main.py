
import os
import json
import hmac
import hashlib
import sqlite3
import secrets
import time

from pathlib import Path
from urllib.parse import parse_qsl

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    UploadFile,
    File,
    Form
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_FILE)

UPLOAD_DIR = BASE_DIR / "uploads"
DATABASE = BASE_DIR / "earntask.db"

UPLOAD_DIR.mkdir(exist_ok=True)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "").strip()

MAX_UPLOAD_SIZE = 5 * 1024 * 1024
MAX_TEXT_LENGTH = 2000

app = FastAPI(title="EarnTask API")


# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://emmanuel21-ai.github.io",
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-Telegram-Init-Data",
        "X-Admin-Key"
    ],
)


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ==================================================
# DATABASE TABLES
# ==================================================

def setup_database():

    with get_db() as connection:

        # Task submissions
        connection.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id TEXT NOT NULL,
                username TEXT,
                task_id TEXT NOT NULL,
                proof_url TEXT,
                note TEXT,
                screenshot TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                reviewed_at INTEGER
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_status
            ON submissions(status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_submissions_telegram
            ON submissions(telegram_id)
        """)

        # Withdrawal requests
        connection.execute("""
            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id TEXT NOT NULL,
                username TEXT,
                amount REAL NOT NULL,
                payment_method TEXT NOT NULL,
                bank_name TEXT NOT NULL,
                account_name TEXT NOT NULL,
                account_number TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                reviewed_at INTEGER,
                admin_note TEXT
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_withdrawals_status
            ON withdrawals(status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_withdrawals_telegram
            ON withdrawals(telegram_id)
        """)


setup_database()


# ==================================================
# TELEGRAM AUTHENTICATION
# ==================================================

def verify_telegram_data(init_data: str):

    if not BOT_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Telegram bot token is not configured."
        )

    if not init_data:
        raise HTTPException(
            status_code=401,
            detail="Telegram authentication is required."
        )

    try:

        values = dict(
            parse_qsl(
                init_data,
                keep_blank_values=True
            )
        )

        received_hash = values.pop("hash", None)

        if not received_hash:
            raise ValueError("Missing hash")

        auth_date = int(values.get("auth_date", "0"))

        current_time = int(time.time())

        if auth_date > current_time + 60:
            raise HTTPException(
                status_code=401,
                detail="Invalid Telegram session date."
            )

        if current_time - auth_date > 86400:
            raise HTTPException(
                status_code=401,
                detail="Telegram session expired. Reopen the app."
            )

        data_check_string = "\n".join(
            f"{key}={value}"
            for key, value in sorted(values.items())
        )

        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            raise ValueError("Invalid Telegram signature")

        user = json.loads(values["user"])

        if not user.get("id"):
            raise ValueError("Missing Telegram user ID")

        return user

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid Telegram authentication."
        )


# ==================================================
# ADMIN AUTHENTICATION
# ==================================================

def require_admin(admin_key: str):

    if not ADMIN_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Admin secret is not configured."
        )

    if not admin_key or not hmac.compare_digest(
        admin_key,
        ADMIN_SECRET
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid admin key."
        )


# ==================================================
# BASIC ROUTES
# ==================================================

@app.get("/")
def home():

    return {
        "app": "EarnTask API",
        "status": "online"
    }


@app.get("/health")
def health():

    return {
        "status": "ok"
    }


@app.get("/api/status")
def status():

    with get_db() as connection:

        total_submissions = connection.execute(
            "SELECT COUNT(*) FROM submissions"
        ).fetchone()[0]

        total_withdrawals = connection.execute(
            "SELECT COUNT(*) FROM withdrawals"
        ).fetchone()[0]

    return {
        "status": "online",
        "proof_submissions": True,
        "total_submissions": total_submissions,
        "withdrawal_requests": True,
        "total_withdrawals": total_withdrawals,
        "payments": False
    }


# ==================================================
# USER: SUBMIT TASK PROOF
# ==================================================

@app.post("/api/submissions")
async def submit_proof(

    task_id: str = Form(...),

    proof_url: str = Form(""),

    note: str = Form(""),

    screenshot: UploadFile | None = File(None),

    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):

    user = verify_telegram_data(telegram_data)

    allowed_tasks = [
        "task01",
        "task02"
    ]

    if task_id not in allowed_tasks:
        raise HTTPException(
            status_code=400,
            detail="Invalid task."
        )

    if (
        not proof_url.strip()
        and not note.strip()
        and screenshot is None
    ):
        raise HTTPException(
            status_code=400,
            detail="Please provide proof."
        )

    if (
        len(proof_url) > MAX_TEXT_LENGTH
        or len(note) > MAX_TEXT_LENGTH
    ):
        raise HTTPException(
            status_code=400,
            detail="Proof information is too long."
        )

    screenshot_name = None

    if screenshot:

        allowed_types = [
            "image/jpeg",
            "image/png",
            "image/webp"
        ]

        if screenshot.content_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="Only JPG, PNG and WEBP images are allowed."
            )

        content = await screenshot.read(
            MAX_UPLOAD_SIZE + 1
        )

        if len(content) > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=400,
                detail="Screenshot must be 5MB or smaller."
            )

        if not content:
            raise HTTPException(
                status_code=400,
                detail="The screenshot is empty."
            )

        extension = {
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/webp": ".webp"
        }[screenshot.content_type]

        screenshot_name = secrets.token_hex(16) + extension

        screenshot_path = UPLOAD_DIR / screenshot_name
        screenshot_path.write_bytes(content)

    with get_db() as connection:

        cursor = connection.execute("""
            INSERT INTO submissions (
                telegram_id,
                username,
                task_id,
                proof_url,
                note,
                screenshot,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (
            str(user["id"]),
            user.get("username", ""),
            task_id,
            proof_url.strip(),
            note.strip(),
            screenshot_name,
            int(time.time())
        ))

        submission_id = cursor.lastrowid

    return {
        "success": True,
        "message": "Proof submitted successfully.",
        "submission_id": submission_id,
        "status": "pending"
    }


# ==================================================
# USER: VIEW OWN SUBMISSIONS
# ==================================================

@app.get("/api/my-submissions")
def my_submissions(

    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )

):

    user = verify_telegram_data(telegram_data)

    with get_db() as connection:

        rows = connection.execute("""
            SELECT
                id,
                task_id,
                proof_url,
                note,
                status,
                created_at,
                reviewed_at
            FROM submissions
            WHERE telegram_id = ?
            ORDER BY id DESC
        """, (
            str(user["id"]),
        )).fetchall()

    return {
        "submissions": [
            dict(row) for row in rows
        ]
    }


# ==================================================
# ADMIN: VIEW ALL SUBMISSIONS
# ==================================================

@app.get("/api/admin/submissions")
def admin_submissions(

    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )

):

    require_admin(admin_key)

    with get_db() as connection:

        rows = connection.execute("""
            SELECT *
            FROM submissions
            ORDER BY id DESC
        """).fetchall()

    submissions = []

    for row in rows:

        item = dict(row)
        item.pop("screenshot", None)

        submissions.append(item)

    return {
        "submissions": submissions,
        "total": len(submissions)
    }


# ==================================================
# ADMIN: VIEW SUBMISSION SCREENSHOT
# ==================================================

@app.get("/api/admin/submissions/{submission_id}/screenshot")
def admin_screenshot(

    submission_id: int,

    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )

):

    require_admin(admin_key)

    with get_db() as connection:

        row = connection.execute("""
            SELECT screenshot
            FROM submissions
            WHERE id = ?
        """, (
            submission_id,
        )).fetchone()

    if not row or not row["screenshot"]:
        raise HTTPException(
            status_code=404,
            detail="Screenshot not found."
        )

    file_path = UPLOAD_DIR / row["screenshot"]

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Screenshot file is missing."
        )

    return FileResponse(file_path)


# ==================================================
# ADMIN: REVIEW TASK SUBMISSION
# ==================================================

@app.post("/api/admin/submissions/{submission_id}/review")
def review_submission(

    submission_id: int,

    status: str = Form(...),

    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )

):

    require_admin(admin_key)

    status = status.strip().lower()

    if status not in ["approved", "rejected"]:
        raise HTTPException(
            status_code=400,
            detail="Status must be approved or rejected."
        )

    with get_db() as connection:

        existing = connection.execute("""
            SELECT id, status
            FROM submissions
            WHERE id = ?
        """, (
            submission_id,
        )).fetchone()

        if not existing:
            raise HTTPException(
                status_code=404,
                detail="Submission not found."
            )

        if existing["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail="This submission has already been reviewed."
            )

        connection.execute("""
            UPDATE submissions
            SET status = ?, reviewed_at = ?
            WHERE id = ?
        """, (
            status,
            int(time.time()),
            submission_id
        ))

    return {
        "success": True,
        "submission_id": submission_id,
        "status": status,
        "message": "Submission review updated."
    }


# ==================================================
# USER: SUBMIT WITHDRAWAL REQUEST
# ==================================================

@app.post("/api/withdrawals")
def submit_withdrawal(

    amount: float = Form(...),

    payment_method: str = Form("bank_transfer"),

    bank_name: str = Form(...),

    account_name: str = Form(...),

    account_number: str = Form(...),

    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )

):

    user = verify_telegram_data(telegram_data)

    if amount != amount or amount <= 0 or amount > 100000000:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid withdrawal amount."
        )

    payment_method = payment_method.strip()
    bank_name = bank_name.strip()
    account_name = account_name.strip()
    account_number = account_number.strip()

    if payment_method != "bank_transfer":
        raise HTTPException(
            status_code=400,
            detail="Unsupported payment method."
        )

    if not all([
        bank_name,
        account_name,
        account_number
    ]):
        raise HTTPException(
            status_code=400,
            detail="Complete all payment details."
        )

    if not account_number.isdigit():
        raise HTTPException(
            status_code=400,
            detail="Account number must contain digits only."
        )

    if (
        len(account_number) > 40
        or len(bank_name) > 100
        or len(account_name) > 100
    ):
        raise HTTPException(
            status_code=400,
            detail="Payment details are too long."
        )

    with get_db() as connection:

        cursor = connection.execute("""
            INSERT INTO withdrawals (
                telegram_id,
                username,
                amount,
                payment_method,
                bank_name,
                account_name,
                account_number,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (
            str(user["id"]),
            user.get("username", ""),
            amount,
            payment_method,
            bank_name,
            account_name,
            account_number,
            int(time.time())
        ))

        withdrawal_id = cursor.lastrowid

    return {
        "success": True,
        "withdrawal_id": withdrawal_id,
        "status": "pending",
        "message": "Withdrawal request submitted successfully."
    }


# ==================================================
# USER: VIEW OWN WITHDRAWALS
# ==================================================

@app.get("/api/my-withdrawals")
def my_withdrawals(

    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )

):

    user = verify_telegram_data(telegram_data)

    with get_db() as connection:

        rows = connection.execute("""
            SELECT
                id,
                amount,
                payment_method,
                bank_name,
                account_name,
                status,
                created_at,
                reviewed_at,
                admin_note
            FROM withdrawals
            WHERE telegram_id = ?
            ORDER BY id DESC
        """, (
            str(user["id"]),
        )).fetchall()

    return {
        "withdrawals": [
            dict(row) for row in rows
        ]
    }


# ==================================================
# ADMIN: VIEW ALL WITHDRAWALS
# ==================================================

@app.get("/api/admin/withdrawals")
def admin_withdrawals(

    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )

):

    require_admin(admin_key)

    with get_db() as connection:

        rows = connection.execute("""
            SELECT *
            FROM withdrawals
            ORDER BY id DESC
        """).fetchall()

    return {
        "withdrawals": [
            dict(row) for row in rows
        ],
        "total": len(rows)
    }


# ==================================================
# ADMIN: REVIEW WITHDRAWAL
# ==================================================

@app.post("/api/admin/withdrawals/{withdrawal_id}/review")
def review_withdrawal(

    withdrawal_id: int,

    status: str = Form(...),

    admin_note: str = Form(""),

    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )

):

    require_admin(admin_key)

    status = status.strip().lower()
    admin_note = admin_note.strip()

    if status not in {"approved", "rejected"}:
        raise HTTPException(
            status_code=400,
            detail="Status must be approved or rejected."
        )

    if len(admin_note) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="Admin note is too long."
        )

    with get_db() as connection:

        existing = connection.execute("""
            SELECT id, status
            FROM withdrawals
            WHERE id = ?
        """, (
            withdrawal_id,
        )).fetchone()

        if not existing:
            raise HTTPException(
                status_code=404,
                detail="Withdrawal request not found."
            )

        if existing["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail="This withdrawal has already been reviewed."
            )

        connection.execute("""
            UPDATE withdrawals
            SET status = ?,
                admin_note = ?,
                reviewed_at = ?
            WHERE id = ?
        """, (
            status,
            admin_note,
            int(time.time()),
            withdrawal_id
        ))

    return {
        "success": True,
        "withdrawal_id": withdrawal_id,
        "status": status,
        "message": "Withdrawal review updated."
    }


# ==================================================
# STARTUP
# ==================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000"))
    )
