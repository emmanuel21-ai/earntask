
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
    FastAPI, Header, HTTPException,
    UploadFile, File, Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

# Load environment variables before reading them.
load_dotenv(BASE_DIR / ".env")

UPLOAD_DIR = BASE_DIR / "uploads"
DATABASE = BASE_DIR / "earntask.db"

UPLOAD_DIR.mkdir(exist_ok=True)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "").strip()
BOT_USERNAME = os.getenv("BOT_USERNAME", "").strip().lstrip("@")

MAX_UPLOAD_SIZE = 5 * 1024 * 1024

TASK_REWARDS = {
    "task01": 0.40,
    "task02": 0.10
}

REFERRAL_REWARD = 0.20
MINIMUM_WITHDRAWAL = 0.50

app = FastAPI(title="EarnTask API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# DATABASE
# ==================================================

def get_db():
    connection = sqlite3.connect(DATABASE, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def setup_database():
    connection = get_db()

    connection.executescript("""
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
        );

        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id TEXT NOT NULL,
            referred_id TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            CHECK (referrer_id != referred_id)
        );

        CREATE INDEX IF NOT EXISTS idx_referrals_referrer
        ON referrals(referrer_id);

        CREATE TABLE IF NOT EXISTS accounts (
            telegram_id TEXT PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS balance_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT NOT NULL,
            amount REAL NOT NULL,
            transaction_type TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            description TEXT,
            created_at INTEGER NOT NULL,
            UNIQUE(source_type, source_id)
        );

        CREATE TABLE IF NOT EXISTS referral_rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id TEXT NOT NULL,
            referred_id TEXT NOT NULL UNIQUE,
            submission_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT NOT NULL,
            amount REAL NOT NULL,
            network TEXT NOT NULL,
            wallet_address TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            refunded INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_withdrawals_user
        ON withdrawals(telegram_id);
    """)

    connection.commit()
    connection.close()


setup_database()


# ==================================================
# BALANCE HELPERS
# ==================================================

def ensure_account(connection, telegram_id):
    connection.execute("""
        INSERT OR IGNORE INTO accounts (telegram_id, balance)
        VALUES (?, 0)
    """, (str(telegram_id),))


def credit_balance(
    connection,
    telegram_id,
    amount,
    transaction_type,
    source_type,
    source_id,
    description
):
    telegram_id = str(telegram_id)

    cursor = connection.execute("""
        INSERT OR IGNORE INTO balance_transactions (
            telegram_id,
            amount,
            transaction_type,
            source_type,
            source_id,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        telegram_id,
        amount,
        transaction_type,
        source_type,
        str(source_id),
        description,
        int(time.time())
    ))

    if cursor.rowcount == 1:
        ensure_account(connection, telegram_id)

        connection.execute("""
            UPDATE accounts
            SET balance = balance + ?
            WHERE telegram_id = ?
        """, (amount, telegram_id))

        return True

    return False


def get_balance(connection, telegram_id):
    ensure_account(connection, telegram_id)

    row = connection.execute("""
        SELECT balance
        FROM accounts
        WHERE telegram_id = ?
    """, (str(telegram_id),)).fetchone()

    return float(row["balance"]) if row else 0.0


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
        values = dict(parse_qsl(
            init_data,
            keep_blank_values=True
        ))

        received_hash = values.pop("hash", None)

        if not received_hash:
            raise ValueError("Missing hash")

        auth_date = int(values.get("auth_date", "0"))

        if auth_date > time.time() + 60:
            raise ValueError("Invalid authentication date")

        if time.time() - auth_date > 86400:
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


def require_admin(admin_key):
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
# WITHDRAWAL REQUEST MODEL
# ==================================================

class WithdrawalRequest(BaseModel):
    amount: float
    network: str
    wallet_address: str


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
    return {"status": "healthy"}


@app.get("/api/status")
def status():
    connection = get_db()

    total = connection.execute(
        "SELECT COUNT(*) FROM submissions"
    ).fetchone()[0]

    connection.close()

    return {
        "status": "online",
        "proof_submissions": True,
        "referrals": True,
        "withdrawals": True,
        "total_submissions": total
    }


# ==================================================
# ACCOUNT BALANCE
# ==================================================

@app.get("/api/account")
def account(
    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):
    user = verify_telegram_data(telegram_data)

    connection = get_db()
    balance = get_balance(connection, user["id"])
    connection.close()

    return {
        "telegram_id": str(user["id"]),
        "balance": round(balance, 2)
    }


# ==================================================
# REFERRAL INFORMATION
# ==================================================

@app.get("/api/referrals")
def referral_information(
    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):
    user = verify_telegram_data(telegram_data)
    user_id = str(user["id"])

    if not BOT_USERNAME:
        raise HTTPException(
            status_code=503,
            detail="BOT_USERNAME is not configured on the backend."
        )

    connection = get_db()

    total = connection.execute("""
        SELECT COUNT(*)
        FROM referrals
        WHERE referrer_id = ?
    """, (user_id,)).fetchone()[0]

    qualified = connection.execute("""
        SELECT COUNT(*)
        FROM referral_rewards
        WHERE referrer_id = ?
    """, (user_id,)).fetchone()[0]

    earnings = connection.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM referral_rewards
        WHERE referrer_id = ?
    """, (user_id,)).fetchone()[0]

    connection.close()

    return {
        "referral_link": (
            f"https://t.me/{BOT_USERNAME}?start={user_id}"
        ),
        "total_referrals": total,
        "qualified_referrals": qualified,
        "referral_earnings": round(float(earnings), 2)
    }


# ==================================================
# SUBMIT TASK PROOF
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

    if task_id not in TASK_REWARDS:
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

    if len(proof_url) > 2000 or len(note) > 2000:
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

        content = await screenshot.read(MAX_UPLOAD_SIZE + 1)

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
        (UPLOAD_DIR / screenshot_name).write_bytes(content)

    connection = get_db()

    cursor = connection.execute("""
        INSERT INTO submissions (
            telegram_id, username, task_id,
            proof_url, note, screenshot,
            status, created_at
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

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "Proof submitted successfully.",
        "submission_id": submission_id,
        "status": "pending"
    }


# ==================================================
# USER SUBMISSION HISTORY
# ==================================================

@app.get("/api/my-submissions")
def my_submissions(
    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):
    user = verify_telegram_data(telegram_data)

    connection = get_db()

    rows = connection.execute("""
        SELECT id, task_id, proof_url, note,
               status, created_at, reviewed_at
        FROM submissions
        WHERE telegram_id = ?
        ORDER BY id DESC
    """, (str(user["id"]),)).fetchall()

    connection.close()

    return {
        "submissions": [dict(row) for row in rows]
    }


# ==================================================
# ADMIN: VIEW SUBMISSIONS
# ==================================================

@app.get("/api/admin/submissions")
def admin_submissions(
    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )
):
    require_admin(admin_key)

    connection = get_db()

    rows = connection.execute("""
        SELECT *
        FROM submissions
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    submissions = []

    for row in rows:
        item = dict(row)
        item.pop("screenshot", None)
        submissions.append(item)

    return {"submissions": submissions}


# ==================================================
# ADMIN: VIEW SCREENSHOT
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

    connection = get_db()

    row = connection.execute("""
        SELECT screenshot
        FROM submissions
        WHERE id = ?
    """, (submission_id,)).fetchone()

    connection.close()

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
# ADMIN: APPROVE OR REJECT SUBMISSION
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

    if status not in ["approved", "rejected"]:
        raise HTTPException(
            status_code=400,
            detail="Status must be approved or rejected."
        )

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        submission = connection.execute("""
            SELECT *
            FROM submissions
            WHERE id = ?
        """, (submission_id,)).fetchone()

        if not submission:
            raise HTTPException(
                status_code=404,
                detail="Submission not found."
            )

        connection.execute("""
            UPDATE submissions
            SET status = ?, reviewed_at = ?
            WHERE id = ?
        """, (status, int(time.time()), submission_id))

        if status == "approved":
            task_id = submission["task_id"]
            user_id = str(submission["telegram_id"])

            reward = TASK_REWARDS.get(task_id, 0)

            if reward:
                credit_balance(
                    connection,
                    user_id,
                    reward,
                    "credit",
                    "task",
                    submission_id,
                    f"Approved {task_id} reward"
                )

            if task_id == "task01":
                referral = connection.execute("""
                    SELECT referrer_id
                    FROM referrals
                    WHERE referred_id = ?
                """, (user_id,)).fetchone()

                if referral:
                    referrer_id = str(referral["referrer_id"])

                    reward_cursor = connection.execute("""
                        INSERT OR IGNORE INTO referral_rewards (
                            referrer_id,
                            referred_id,
                            submission_id,
                            amount,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        referrer_id,
                        user_id,
                        submission_id,
                        REFERRAL_REWARD,
                        int(time.time())
                    ))

                    if reward_cursor.rowcount == 1:
                        credit_balance(
                            connection,
                            referrer_id,
                            REFERRAL_REWARD,
                            "credit",
                            "referral",
                            user_id,
                            "Task 01 referral bonus"
                        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "success": True,
        "submission_id": submission_id,
        "status": status,
        "message": "Submission review updated."
    }


# ==================================================
# USER: REQUEST WITHDRAWAL
# ==================================================

@app.post("/api/withdrawals")
def request_withdrawal(
    data: WithdrawalRequest,
    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):
    user = verify_telegram_data(telegram_data)

    amount = round(data.amount, 2)
    network = data.network.upper()
    wallet_address = data.wallet_address.strip()

    if amount < MINIMUM_WITHDRAWAL:
        raise HTTPException(
            status_code=400,
            detail="Minimum withdrawal is 0.50 USDT."
        )

    if network not in ["TRC20", "BEP20", "ERC20"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid USDT network."
        )

    if not wallet_address or len(wallet_address) > 200:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid wallet address."
        )

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        balance = get_balance(connection, user["id"])

        if balance < amount:
            raise HTTPException(
                status_code=400,
                detail="Insufficient available balance."
            )

        cursor = connection.execute("""
            INSERT INTO withdrawals (
                telegram_id,
                amount,
                network,
                wallet_address,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, 'pending', ?)
        """, (
            str(user["id"]),
            amount,
            network,
            wallet_address,
            int(time.time())
        ))

        withdrawal_id = cursor.lastrowid

        connection.execute("""
            UPDATE accounts
            SET balance = balance - ?
            WHERE telegram_id = ?
        """, (amount, str(user["id"])))

        connection.execute("""
            INSERT INTO balance_transactions (
                telegram_id, amount, transaction_type,
                source_type, source_id, description, created_at
            )
            VALUES (?, ?, 'debit', 'withdrawal', ?, ?, ?)
        """, (
            str(user["id"]),
            -amount,
            str(withdrawal_id),
            "Withdrawal request",
            int(time.time())
        ))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "success": True,
        "withdrawal_id": withdrawal_id,
        "message": "Withdrawal request submitted for review."
    }


# ==================================================
# USER: WITHDRAWAL HISTORY
# ==================================================

@app.get("/api/my-withdrawals")
def my_withdrawals(
    telegram_data: str = Header(
        default="",
        alias="X-Telegram-Init-Data"
    )
):
    user = verify_telegram_data(telegram_data)

    connection = get_db()

    rows = connection.execute("""
        SELECT id, amount, network, wallet_address,
               status, created_at, reviewed_at
        FROM withdrawals
        WHERE telegram_id = ?
        ORDER BY id DESC
    """, (str(user["id"]),)).fetchall()

    connection.close()

    return {
        "withdrawals": [dict(row) for row in rows]
    }


# ==================================================
# ADMIN: VIEW WITHDRAWALS
# ==================================================

@app.get("/api/admin/withdrawals")
def admin_withdrawals(
    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )
):
    require_admin(admin_key)

    connection = get_db()

    rows = connection.execute("""
        SELECT *
        FROM withdrawals
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return {
        "withdrawals": [dict(row) for row in rows]
    }


# ==================================================
# ADMIN: APPROVE OR REJECT WITHDRAWAL
# ==================================================

@app.post("/api/admin/withdrawals/{withdrawal_id}/review")
def review_withdrawal(
    withdrawal_id: int,
    status: str = Form(...),
    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )
):
    require_admin(admin_key)

    if status not in ["approved", "rejected"]:
        raise HTTPException(
            status_code=400,
            detail="Status must be approved or rejected."
        )

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        withdrawal = connection.execute("""
            SELECT *
            FROM withdrawals
            WHERE id = ?
        """, (withdrawal_id,)).fetchone()

        if not withdrawal:
            raise HTTPException(
                status_code=404,
                detail="Withdrawal not found."
            )

        if withdrawal["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail="This withdrawal has already been reviewed."
            )

        connection.execute("""
            UPDATE withdrawals
            SET status = ?, reviewed_at = ?
            WHERE id = ?
        """, (status, int(time.time()), withdrawal_id))

        if status == "rejected" and not withdrawal["refunded"]:
            user_id = str(withdrawal["telegram_id"])
            amount = float(withdrawal["amount"])

            ensure_account(connection, user_id)

            connection.execute("""
                UPDATE accounts
                SET balance = balance + ?
                WHERE telegram_id = ?
            """, (amount, user_id))

            connection.execute("""
                INSERT INTO balance_transactions (
                    telegram_id, amount, transaction_type,
                    source_type, source_id, description, created_at
                )
                VALUES (?, ?, 'credit', 'withdrawal_refund', ?, ?, ?)
            """, (
                user_id,
                amount,
                str(withdrawal_id),
                "Rejected withdrawal refund",
                int(time.time())
            ))

            connection.execute("""
                UPDATE withdrawals
                SET refunded = 1
                WHERE id = ?
            """, (withdrawal_id,))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "success": True,
        "withdrawal_id": withdrawal_id,
        "status": status,
        "message": "Withdrawal review updated."
    }


# ==================================================
# ADMIN: REFERRAL BONUS AUDIT
# ==================================================

@app.get("/api/admin/referrals")
def admin_referrals(
    admin_key: str = Header(
        default="",
        alias="X-Admin-Key"
    )
):
    require_admin(admin_key)

    connection = get_db()

    rows = connection.execute("""
        SELECT *
        FROM referral_rewards
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return {
        "referral_rewards": [dict(row) for row in rows]
    }
