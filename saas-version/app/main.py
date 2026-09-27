import datetime

from fastapi import FastAPI, Depends, HTTPException, Request, BackgroundTasks, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from . import config, models, payments, domain_verify
from .auth import (hash_password, verify_password, create_access_token,
                    get_current_user, get_current_user_optional)
from .access_control import require_scan_access, can_scan, days_left_in_trial, has_active_subscription
from .database import Base, engine, get_db
from .scan_runner import run_scan_job

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NaijaVulnScan")
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))

COOKIE_NAME = "session_token"


# ----------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------

@app.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request, "trial_days": config.TRIAL_DAYS})


@app.post("/signup")
def signup(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    user = models.User(email=email, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return response


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token(user.id)
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(COOKIE_NAME)
    return response


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    domains = db.query(models.Domain).filter(models.Domain.user_id == user.id).all()
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == user.id)
        .order_by(models.Scan.created_at.desc())
        .limit(20)
        .all()
    )
    allowed, reason = can_scan(user)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "domains": domains,
        "scans": scans,
        "can_scan": allowed,
        "block_reason": reason,
        "trial_days_left": days_left_in_trial(user),
        "has_subscription": has_active_subscription(user),
    })


# ----------------------------------------------------------------------
# Domains + verification
# ----------------------------------------------------------------------

@app.post("/domains")
def add_domain(hostname: str = Form(...), user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    hostname = hostname.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    domain = models.Domain(user_id=user.id, hostname=hostname)
    db.add(domain)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@app.get("/domains/{domain_id}/verify", response_class=HTMLResponse)
def verify_instructions(request: Request, domain_id: int,
                         user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    domain = db.query(models.Domain).filter(models.Domain.id == domain_id, models.Domain.user_id == user.id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")

    return templates.TemplateResponse("verify_domain.html", {
        "request": request,
        "domain": domain,
        "dns_instructions": domain_verify.dns_txt_instructions(domain.hostname, domain.verification_token),
        "file_instructions": domain_verify.file_upload_instructions(domain.hostname, domain.verification_token),
    })


@app.post("/domains/{domain_id}/verify")
def check_verification(domain_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    domain = db.query(models.Domain).filter(models.Domain.id == domain_id, models.Domain.user_id == user.id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")

    if domain_verify.verify_domain(domain.hostname, domain.verification_token):
        domain.verified = True
        domain.verified_at = datetime.datetime.utcnow()
        db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


# ----------------------------------------------------------------------
# Scans - this is the part gated by require_scan_access (trial/subscription)
# ----------------------------------------------------------------------

@app.post("/scans")
def start_scan(
    background_tasks: BackgroundTasks,
    domain_id: int = Form(...),
    modules: str = Form("ports,ssl,headers"),
    user: models.User = Depends(require_scan_access),
    db: Session = Depends(get_db),
):
    domain = db.query(models.Domain).filter(models.Domain.id == domain_id, models.Domain.user_id == user.id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")
    if not domain.verified:
        raise HTTPException(status_code=403, detail="Verify domain ownership before scanning it.")

    scan = models.Scan(user_id=user.id, domain_id=domain.id, modules=modules)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_scan_job, scan.id)

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
def view_report(scan_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == user.id).first()
    if not scan or not scan.report_filename:
        raise HTTPException(status_code=404, detail="Report not ready or not found.")
    filepath = config.REPORTS_DIR / scan.report_filename
    return FileResponse(filepath, media_type="text/html")


# ----------------------------------------------------------------------
# Billing
# ----------------------------------------------------------------------

@app.get("/billing", response_class=HTMLResponse)
def billing_page(request: Request, user: models.User = Depends(get_current_user)):
    return templates.TemplateResponse("billing.html", {
        "request": request,
        "price": config.SUBSCRIPTION_PRICE_NGN,
        "period_days": config.SUBSCRIPTION_PERIOD_DAYS,
    })


@app.post("/billing/start")
async def start_payment(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    reference = payments.generate_reference()
    payment = models.Payment(user_id=user.id, reference=reference, amount_ngn=config.SUBSCRIPTION_PRICE_NGN)
    db.add(payment)
    db.commit()

    result = await payments.initialize_transaction(user.email, config.SUBSCRIPTION_PRICE_NGN, reference)
    auth_url = result.get("data", {}).get("authorization_url")
    if not auth_url:
        raise HTTPException(status_code=502, detail="Could not start payment with Paystack.")
    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@app.get("/billing/callback")
async def billing_callback(reference: str, db: Session = Depends(get_db)):
    """
    Paystack redirects the user's browser here after payment - but we
    NEVER trust this alone (a user could hit this URL manually). We
    re-verify with Paystack server-to-server before granting access.
    The webhook below is the authoritative source; this is just a nicer
    instant experience for the user instead of waiting for the webhook.
    """
    result = await payments.verify_transaction(reference)
    data = result.get("data", {})

    payment = db.query(models.Payment).filter(models.Payment.reference == reference).first()
    if payment and data.get("status") == "success":
        _confirm_payment(payment, db)

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@app.post("/billing/webhook")
async def paystack_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    signature = request.headers.get("x-paystack-signature", "")

    if not payments.verify_webhook_signature(body, signature):
        raise HTTPException(status_code=400, detail="Invalid signature.")

    event = await request.json()
    if event.get("event") == "charge.success":
        reference = event["data"]["reference"]
        payment = db.query(models.Payment).filter(models.Payment.reference == reference).first()
        if payment and payment.status != models.PaymentStatus.success:
            _confirm_payment(payment, db)

    return {"status": "ok"}


def _confirm_payment(payment: models.Payment, db: Session):
    payment.status = models.PaymentStatus.success
    payment.confirmed_at = datetime.datetime.utcnow()

    user = payment.user
    now = datetime.datetime.utcnow()
    # Extend from "now" or from existing expiry if they're renewing early, whichever is later.
    base = user.subscription_expires_at if (user.subscription_expires_at and user.subscription_expires_at > now) else now
    user.subscription_expires_at = base + datetime.timedelta(days=config.SUBSCRIPTION_PERIOD_DAYS)
    user.subscription_status = models.SubscriptionStatus.active

    db.commit()
