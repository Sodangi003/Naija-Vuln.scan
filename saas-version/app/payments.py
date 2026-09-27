"""
Paystack integration. Get your keys from https://dashboard.paystack.com
(test keys start with sk_test_/pk_test_ - use these until you're ready to
go live; they let you simulate payments without real money).
"""

import hashlib
import hmac
import secrets

import httpx

from . import config


def generate_reference() -> str:
    return f"nvs_{secrets.token_hex(12)}"


async def initialize_transaction(email: str, amount_ngn: int, reference: str) -> dict:
    """
    Kicks off a Paystack payment. Returns Paystack's response, which
    includes an `authorization_url` you redirect the user to in order to
    actually pay.
    """
    url = f"{config.PAYSTACK_BASE_URL}/transaction/initialize"
    headers = {"Authorization": f"Bearer {config.PAYSTACK_SECRET_KEY}"}
    payload = {
        "email": email,
        "amount": amount_ngn * 100,  # Paystack expects kobo, not naira
        "reference": reference,
        "callback_url": f"{config.APP_BASE_URL}/billing/callback",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload, headers=headers, timeout=15.0)
        resp.raise_for_status()
        return resp.json()


async def verify_transaction(reference: str) -> dict:
    """Confirms a transaction's real status directly with Paystack (never
    trust the client-side redirect alone - always re-check server to server)."""
    url = f"{config.PAYSTACK_BASE_URL}/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {config.PAYSTACK_SECRET_KEY}"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, timeout=15.0)
        resp.raise_for_status()
        return resp.json()


def verify_webhook_signature(request_body: bytes, signature_header: str) -> bool:
    """
    Paystack signs webhook payloads with your secret key - always verify
    this before trusting a webhook, or anyone could POST a fake
    'payment succeeded' event to your server.
    """
    computed = hmac.new(
        config.PAYSTACK_SECRET_KEY.encode("utf-8"),
        request_body,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(computed, signature_header or "")
