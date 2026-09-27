"""
This module answers exactly one question: "is this user allowed to run a
scan right now?" - and it's the one piece of logic that actually enforces
your monetization, so it deliberately does everything server-side against
the database, never trusting anything the client sends.
"""

import datetime

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from . import config, models
from .auth import get_current_user
from .database import get_db


def days_left_in_trial(user: models.User) -> int:
    elapsed = datetime.datetime.utcnow() - user.trial_started_at
    remaining = config.TRIAL_DAYS - elapsed.days
    return max(0, remaining)


def has_active_subscription(user: models.User) -> bool:
    return (
        user.subscription_status == models.SubscriptionStatus.active
        and user.subscription_expires_at is not None
        and user.subscription_expires_at > datetime.datetime.utcnow()
    )


def can_scan(user: models.User) -> tuple[bool, str]:
    """Returns (allowed, reason_if_not)."""
    if has_active_subscription(user):
        return True, ""
    if user.subscription_status == models.SubscriptionStatus.trial and days_left_in_trial(user) > 0:
        return True, ""
    return False, "Your free trial has ended and you don't have an active subscription."


def require_scan_access(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> models.User:
    """FastAPI dependency: raises 402 Payment Required if the user can't scan."""
    allowed, reason = can_scan(user)
    if not allowed:
        # Keep the DB status in sync so the dashboard shows the right thing too.
        if user.subscription_status != models.SubscriptionStatus.expired:
            user.subscription_status = models.SubscriptionStatus.expired
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=reason + " Visit /billing to subscribe.",
        )
    return user
