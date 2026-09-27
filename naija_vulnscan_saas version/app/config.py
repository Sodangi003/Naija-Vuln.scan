"""
Central configuration. All secrets come from environment variables /
a .env file - never hardcode API keys, even in a private repo.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")  # no-op if the file doesn't exist yet

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# --- Core ---
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE-ME-INSECURE-DEV-ONLY-SECRET")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/naijavulnscan.db")

# --- Trial / subscription ---
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "7"))
SUBSCRIPTION_PRICE_NGN = int(os.getenv("SUBSCRIPTION_PRICE_NGN", "5000"))  # per 30 days, in Naira
SUBSCRIPTION_PERIOD_DAYS = int(os.getenv("SUBSCRIPTION_PERIOD_DAYS", "30"))

# --- Paystack ---
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")  # sk_test_xxx or sk_live_xxx
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY", "")  # pk_test_xxx or pk_live_xxx
PAYSTACK_BASE_URL = "https://api.paystack.co"

# --- App URLs (used for payment callback + verification instructions) ---
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

# --- JWT ---
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
