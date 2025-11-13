"""Secure credential management dashboard for Marksaint."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from functools import wraps
from hashlib import pbkdf2_hmac
from io import BytesIO
from typing import List

import pyotp
from cryptography.fernet import Fernet
from flask import (Flask, flash, redirect, render_template, request, send_file,
                   session, url_for)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "marksaint.db")
PASSWORD_ROTATION_DAYS = 90
WEAK_PASSWORD_LENGTH = 12
DEFAULT_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # demo secret - override via env


def storage_cipher() -> Fernet:
    secret = os.environ.get("MARKSAINT_STORAGE_KEY")
    if not secret:
        raise RuntimeError(
            "Set MARKSAINT_STORAGE_KEY with a base64 urlsafe 32-byte key to proteger os dados."
        )
    try:
        return Fernet(secret)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("Invalid MARKSAINT_STORAGE_KEY. Provide a valid Fernet key.") from exc


def totp() -> pyotp.TOTP:
    secret = os.environ.get("MARKSAINT_TOTP_SECRET", DEFAULT_TOTP_SECRET)
    return pyotp.TOTP(secret)


def admin_password_hash() -> str:
    return os.environ.get(
        "MARKSAINT_ADMIN_PASSWORD_HASH",
        generate_password_hash("Admin#2024"),
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("MARKSAINT_APP_SECRET", os.urandom(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


app = create_app()
db = SQLAlchemy(app)


class EmailProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(150), unique=True, nullable=False)
    owner = db.Column(db.String(120))
    purpose = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accounts = db.relationship("Account", backref="email_profile", lazy=True)

    @property
    def is_used(self) -> bool:
        return bool(self.accounts)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    email_profile_id = db.Column(db.Integer, db.ForeignKey("email_profile.id"))
    app_name = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    last_rotation = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)

    def decrypt_password(self) -> str:
        return storage_cipher().decrypt(self.encrypted_password).decode()


@dataclass
class SecurityInsight:
    label: str
    description: str
    severity: str


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            flash("Sessão expirada. Realize login seguro.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


def fetch_accounts(query: str | None, status: str) -> List[Account]:
    q = Account.query
    if query:
        like = f"%{query.strip()}%"
        q = q.filter(or_(Account.email.ilike(like), Account.app_name.ilike(like)))
    if status == "due":
        limit = date.today() - timedelta(days=PASSWORD_ROTATION_DAYS)
        q = q.filter(Account.last_rotation <= limit)
    elif status == "healthy":
        limit = date.today() - timedelta(days=PASSWORD_ROTATION_DAYS)
        q = q.filter(Account.last_rotation > limit)
    return q.order_by(Account.app_name.asc()).all()


def vulnerable_accounts(accounts: List[Account]) -> List[SecurityInsight]:
    cipher = storage_cipher()
    insights: List[SecurityInsight] = []
    rotation_limit = date.today() - timedelta(days=PASSWORD_ROTATION_DAYS)
    for acc in accounts:
        if acc.last_rotation <= rotation_limit:
            insights.append(
                SecurityInsight(
                    label=f"Rotação pendente - {acc.app_name}",
                    description=(
                        "Senha não foi rotacionada nos últimos "
                        f"{PASSWORD_ROTATION_DAYS} dias. Alinhe com o runbook de resposta."
                    ),
                    severity="high",
                )
            )
        password = cipher.decrypt(acc.encrypted_password).decode()
        if len(password) < WEAK_PASSWORD_LENGTH:
            insights.append(
                SecurityInsight(
                    label=f"Senha fraca em {acc.app_name}",
                    description="Utilize 12+ caracteres e combine letras, números e símbolos.",
                    severity="medium",
                )
            )
    return insights


def best_practices() -> List[str]:
    return [
        "Habilite autenticação de dois fatores em todos os serviços críticos.",
        "Rotacione senhas críticas a cada 90 dias ou após incidentes.",
        "Utilize senhas únicas por aplicativo e adote frases longas.",
        "Restrinja o acesso administrativo e registre auditorias periódicas.",
        "Mantenha backups criptografados dos cofre corporativo.",
    ]


def derive_export_key(passphrase: str, salt: bytes) -> bytes:
    raw = pbkdf2_hmac("sha256", passphrase.encode(), salt, 390000, dklen=32)
    return base64.urlsafe_b64encode(raw)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        otp = request.form.get("otp", "")
        if not check_password_hash(admin_password_hash(), password):
            flash("Credenciais inválidas.", "danger")
        elif not totp().verify(otp):
            flash("Token de autenticação multifator inválido ou expirado.", "danger")
        else:
            session["authenticated"] = True
            session.permanent = True
            flash("Bem-vindo ao cofre de credenciais corporativo.", "success")
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão finalizada.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    accounts = Account.query.all()
    total_accounts = len(accounts)
    rotation_due = sum(
        1 for acc in accounts if acc.last_rotation <= date.today() - timedelta(days=PASSWORD_ROTATION_DAYS)
    )
    total_emails = EmailProfile.query.count()
    unused_emails = EmailProfile.query.filter(~EmailProfile.accounts.any()).count()
    insights = vulnerable_accounts(accounts)
    return render_template(
        "dashboard.html",
        total_accounts=total_accounts,
        rotation_due=rotation_due,
        total_emails=total_emails,
        unused_emails=unused_emails,
        insights=insights,
        best_practices=best_practices(),
    )


@app.route("/accounts")
@login_required
def accounts_list():
    query = request.args.get("q")
    status = request.args.get("status", "all")
    accounts = fetch_accounts(query, status)
    return render_template("accounts/list.html", accounts=accounts, query=query, status=status)


@app.route("/accounts/new", methods=["GET", "POST"])
@login_required
def accounts_create():
    if request.method == "POST":
        return save_account()
    profiles = EmailProfile.query.order_by(EmailProfile.address.asc()).all()
    return render_template("accounts/form.html", account=None, email_profiles=profiles)


@app.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
@login_required
def accounts_edit(account_id: int):
    account = Account.query.get_or_404(account_id)
    if request.method == "POST":
        return save_account(account)
    profiles = EmailProfile.query.order_by(EmailProfile.address.asc()).all()
    return render_template("accounts/form.html", account=account, email_profiles=profiles)


def save_account(account: Account | None = None):
    cipher = storage_cipher()
    email = request.form.get("email", "").strip()
    app_name = request.form.get("app_name", "").strip()
    password = request.form.get("password", "").strip()
    rotation = request.form.get("last_rotation", "")
    notes = request.form.get("notes", "").strip() or None
    if not all([email, app_name, password, rotation]):
        flash("Preencha todos os campos obrigatórios.", "warning")
        return redirect(request.referrer or url_for("accounts_list"))
    rotation_date = datetime.strptime(rotation, "%Y-%m-%d").date()
    encrypted_password = cipher.encrypt(password.encode())
    profile = get_or_create_email_profile(email)
    if not account:
        account = Account()
        db.session.add(account)
    account.email = profile.address
    account.email_profile = profile
    account.app_name = app_name
    account.encrypted_password = encrypted_password
    account.last_rotation = rotation_date
    account.notes = notes
    db.session.commit()
    flash("Credencial salva com criptografia forte.", "success")
    return redirect(url_for("accounts_list"))


def get_or_create_email_profile(address: str) -> EmailProfile:
    normalized = address.lower()
    profile = EmailProfile.query.filter(EmailProfile.address == normalized).first()
    if profile:
        return profile
    profile = EmailProfile(address=normalized)
    db.session.add(profile)
    db.session.flush()
    return profile


@app.route("/accounts/<int:account_id>/delete", methods=["POST"])
@login_required
def accounts_delete(account_id: int):
    account = Account.query.get_or_404(account_id)
    db.session.delete(account)
    db.session.commit()
    flash("Credencial removida com sucesso.", "info")
    return redirect(url_for("accounts_list"))


@app.route("/emails")
@login_required
def emails_list():
    query = request.args.get("q", "").strip()
    status = request.args.get("status", "all")
    q = EmailProfile.query.options(selectinload(EmailProfile.accounts))
    if query:
        like = f"%{query}%"
        q = q.filter(
            or_(
                EmailProfile.address.ilike(like),
                EmailProfile.purpose.ilike(like),
                EmailProfile.owner.ilike(like),
            )
        )
    profiles = q.order_by(EmailProfile.address.asc()).all()
    if status == "used":
        profiles = [profile for profile in profiles if profile.accounts]
    elif status == "unused":
        profiles = [profile for profile in profiles if not profile.accounts]
    return render_template(
        "emails/list.html",
        profiles=profiles,
        query=query,
        status=status,
    )


@app.route("/emails/new", methods=["GET", "POST"])
@login_required
def emails_create():
    if request.method == "POST":
        return save_email_profile()
    return render_template("emails/form.html", profile=None)


@app.route("/emails/<int:profile_id>/edit", methods=["GET", "POST"])
@login_required
def emails_edit(profile_id: int):
    profile = EmailProfile.query.get_or_404(profile_id)
    if request.method == "POST":
        return save_email_profile(profile)
    return render_template("emails/form.html", profile=profile)


def save_email_profile(profile: EmailProfile | None = None):
    address = request.form.get("address", "").strip().lower()
    owner = request.form.get("owner", "").strip() or None
    purpose = request.form.get("purpose", "").strip() or None
    notes = request.form.get("notes", "").strip() or None
    if not address:
        flash("Informe um endereço de e-mail corporativo.", "warning")
        return redirect(request.referrer or url_for("emails_list"))
    try:
        if not profile:
            profile = EmailProfile(address=address)
            db.session.add(profile)
        profile.address = address
        profile.owner = owner
        profile.purpose = purpose
        profile.notes = notes
        db.session.commit()
        flash("E-mail cadastrado com sucesso.", "success")
    except IntegrityError:
        db.session.rollback()
        flash("Este e-mail já está registrado no cofre.", "danger")
        return redirect(request.referrer or url_for("emails_list"))
    return redirect(url_for("emails_list"))


@app.route("/emails/<int:profile_id>/delete", methods=["POST"])
@login_required
def emails_delete(profile_id: int):
    profile = EmailProfile.query.get_or_404(profile_id)
    if profile.accounts:
        flash("Remova os vínculos antes de excluir o e-mail.", "warning")
        return redirect(url_for("emails_list"))
    db.session.delete(profile)
    db.session.commit()
    flash("E-mail removido.", "info")
    return redirect(url_for("emails_list"))


@app.route("/export", methods=["GET", "POST"])
@login_required
def export_data():
    if request.method == "POST":
        passphrase = request.form.get("passphrase", "")
        if len(passphrase) < 10:
            flash("Informe uma frase-senha com pelo menos 10 caracteres.", "warning")
            return redirect(url_for("export_data"))
        salt = os.urandom(16)
        key = derive_export_key(passphrase, salt)
        cipher = Fernet(key)
        payload = []
        storage = storage_cipher()
        for acc in Account.query.order_by(Account.app_name).all():
            payload.append(
                {
                    "email": acc.email,
                    "email_profile": acc.email_profile.address if acc.email_profile else acc.email,
                    "app_name": acc.app_name,
                    "password": storage.decrypt(acc.encrypted_password).decode(),
                    "last_rotation": acc.last_rotation.isoformat(),
                    "notes": acc.notes,
                }
            )
        blob = json.dumps(payload, indent=2).encode()
        encrypted_blob = cipher.encrypt(blob)
        buffer = BytesIO()
        buffer.write(salt + encrypted_blob)
        buffer.seek(0)
        filename = f"marksaint-export-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bin"
        return send_file(
            buffer,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=filename,
        )
    return render_template("export.html")


@app.template_filter("rotation_status")
def rotation_status(last_rotation: date) -> str:
    days_since = (date.today() - last_rotation).days
    if days_since >= PASSWORD_ROTATION_DAYS:
        return f"Atrasado ({days_since} dias)"
    return f"Em dia ({days_since} dias)"


@app.context_processor
def inject_globals():
    return {
        "PASSWORD_ROTATION_DAYS": PASSWORD_ROTATION_DAYS,
    }


with app.app_context():
    db.create_all()
    info = db.session.execute(text("PRAGMA table_info(account)")).fetchall()
    has_email_profile_col = any(column[1] == "email_profile_id" for column in info)
    if not has_email_profile_col:
        db.session.execute(text("ALTER TABLE account ADD COLUMN email_profile_id INTEGER"))
        db.session.commit()
    for account in Account.query.filter(Account.email_profile_id.is_(None)).all():
        profile = get_or_create_email_profile(account.email)
        account.email_profile = profile
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
