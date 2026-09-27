import datetime
import enum
import secrets

from sqlalchemy import (Column, Integer, String, DateTime, Boolean,
                         ForeignKey, Enum, Text)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow():
    return datetime.datetime.utcnow()


class SubscriptionStatus(str, enum.Enum):
    trial = "trial"
    active = "active"
    expired = "expired"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    trial_started_at = Column(DateTime, default=utcnow)
    subscription_status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.trial)
    subscription_expires_at = Column(DateTime, nullable=True)

    paystack_customer_code = Column(String(100), nullable=True)

    domains = relationship("Domain", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="user", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    verification_token = Column(String(64), default=lambda: secrets.token_hex(16))
    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    owner = relationship("User", back_populates="domains")
    scans = relationship("Scan", back_populates="domain", cascade="all, delete-orphan")


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    modules = Column(String(100), default="ports,ssl,headers")
    status = Column(Enum(ScanStatus), default=ScanStatus.queued)
    report_filename = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="scans")
    domain = relationship("Domain", back_populates="scans")


class PaymentStatus(str, enum.Enum):
    pending = "pending"
    success = "success"
    failed = "failed"


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reference = Column(String(100), unique=True, nullable=False)
    amount_ngn = Column(Integer, nullable=False)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.pending)
    created_at = Column(DateTime, default=utcnow)
    confirmed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="payments")
