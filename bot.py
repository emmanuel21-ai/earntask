
import os
import sqlite3
import time

from pathlib import Path
from dotenv import load_dotenv

from telegram import (
    Update,
    ReplyKeyboardMarkup,
    KeyboardButton,
    WebAppInfo
)

from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(dotenv_path=BASE_DIR / ".env")

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

WEB_APP_URL = "https://emmanuel21-ai.github.io/earntask/"

DATABASE = BASE_DIR / "earntask.db"


# ==================================================
# REFERRAL DATABASE
# ==================================================

def setup_referrals():

    with sqlite3.connect(DATABASE) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_id TEXT NOT NULL,
                referred_id TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                CHECK (referrer_id != referred_id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_referrals_referrer
            ON referrals(referrer_id)
        """)


def record_referral(referrer_id, referred_id):

    referrer_id = str(referrer_id)
    referred_id = str(referred_id)

    if not referrer_id.isdigit():
        return False

    if not referred_id.isdigit():
        return False

    if referrer_id == referred_id:
        return False

    with sqlite3.connect(DATABASE) as connection:

        cursor = connection.execute("""
            INSERT OR IGNORE INTO referrals (
                referrer_id,
                referred_id,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            referrer_id,
            referred_id,
            int(time.time())
        ))

        return cursor.rowcount == 1


setup_referrals()


# ==================================================
# START COMMAND
# ==================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    user = update.effective_user

    if not user or not update.message:
        return

    # Record referral silently in the background
    if context.args:

        referral_code = context.args[0].strip()

        if referral_code.isdigit():

            record_referral(
                referral_code,
                user.id
            )

    # Get username
    if user.username:
        username = f"@{user.username}"
    else:
        username = user.first_name or "there"

    # Normal welcome message ONLY
    message = (
        "🎉 Welcome to EarnTask!\n\n"
        f"Hello, {username}! Welcome to EarnTask, where you "
        "can explore available tasks, complete them and earn "
        "rewards in USDT. Track your earnings and submit "
        "withdrawal requests as you progress. We're glad to "
        "have you here. Let's get started! 🚀"
    )

    # Mini App button
    keyboard = [
        [
            KeyboardButton(
                "Open EarnTask",
                web_app=WebAppInfo(url=WEB_APP_URL)
            )
        ]
    ]

    reply_markup = ReplyKeyboardMarkup(
        keyboard,
        resize_keyboard=True,
        is_persistent=True
    )

    await update.message.reply_text(
        message,
        reply_markup=reply_markup,
        disable_web_page_preview=True
    )


# ==================================================
# BOT INITIALIZATION
# ==================================================

if not TOKEN:
    raise RuntimeError(
        "TELEGRAM_BOT_TOKEN is not configured in .env"
    )


app = ApplicationBuilder().token(TOKEN).build()

app.add_handler(
    CommandHandler("start", start)
)


# ==================================================
# RUN BOT
# ==================================================

print("EarnTask bot is running...")

app.run_polling()
