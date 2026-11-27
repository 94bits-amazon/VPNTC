import os
import base64
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _get_cipher() -> Fernet:
    """Deriva uma chave Fernet válida de 32 bytes a partir da SECRET_KEY do ambiente."""
    secret = os.getenv("SECRET_KEY", "dev-secret-key").encode("utf-8")
    digest = hashlib.sha256(secret).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class SystemSetting(db.Model):
    __tablename__ = "system_settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    is_secret = db.Column(db.Boolean, default=False, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    @classmethod
    def get(cls, key: str, default: str = "") -> str:
        """Lê do banco de dados; se não existir, faz fallback para variável de ambiente (.env)."""
        row = cls.query.filter_by(key=key).first()
        if row and row.value is not None:
            if row.is_secret and row.value != "":
                try:
                    return _get_cipher().decrypt(row.value.encode("utf-8")).decode("utf-8")
                except Exception:
                    return ""
            return row.value
        return os.getenv(key, default)

    @classmethod
    def set(cls, key: str, value: str, is_secret: bool = False) -> None:
        row = cls.query.filter_by(key=key).first()
        stored_val = value
        if is_secret and value:
            stored_val = _get_cipher().encrypt(value.encode("utf-8")).decode("utf-8")

        if row:
            # Se for campo secreto e vier vazio no form, mantém a senha anterior salva
            if is_secret and not value:
                return
            row.value = stored_val
            row.is_secret = is_secret
        else:
            row = cls(key=key, value=stored_val, is_secret=is_secret)
            db.session.add(row)


class VpnProfile(db.Model):
    """Grupos de VPN do Active Directory cadastrados dinamicamente na tela /config."""
    __tablename__ = "vpn_profiles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    group_dn = db.Column(db.String(300), nullable=False, unique=True)
    badge_color = db.Column(db.String(20), nullable=False, default="primary")  # primary, info, warning, success, secondary
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)


class VpnAccess(db.Model):
    __tablename__ = "vpn_access"

    id = db.Column(db.Integer, primary_key=True)
    sam_account_name = db.Column(db.String(64), nullable=False, index=True)
    display_name = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(150), nullable=True)
    user_dn = db.Column(db.String(300), nullable=False)

    profile_id = db.Column(db.Integer, db.ForeignKey("vpn_profiles.id"), nullable=False)
    profile = db.relationship("VpnProfile", backref=db.backref("accesses", lazy=True))

    duration_days = db.Column(db.Integer, nullable=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # 'ACTIVE', 'EXPIRED', 'REVOKED'
    status = db.Column(db.String(20), nullable=False, default="ACTIVE", index=True)
    last_ticket = db.Column(db.String(50), nullable=False)
    granted_by = db.Column(db.String(64), nullable=False)

    # Campos para telemetria do FortiAnalyzer
    last_faz_seen = db.Column(db.DateTime, nullable=True)
    total_faz_seconds = db.Column(db.Integer, nullable=False, default=0)
    is_online_now = db.Column(db.Boolean, nullable=False, default=False)

    __table_args__ = (
        db.UniqueConstraint("sam_account_name", "profile_id", name="uq_user_profile"),
    )

    @property
    def days_remaining(self) -> int:
        delta = self.expires_at - datetime.now()
        return max(0, delta.days + (1 if delta.seconds > 0 and delta.days >= 0 else 0))


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    # GRANTED, RENEWED, EXPIRED_AUTO, REVOKED_MANUAL, CONFIG_UPDATED
    action = db.Column(db.String(30), nullable=False)
    target_user = db.Column(db.String(64), nullable=False, index=True)
    target_name = db.Column(db.String(150), nullable=True)
    vpn_profile_name = db.Column(db.String(80), nullable=False)
    duration_days = db.Column(db.Integer, nullable=True)
    ticket_number = db.Column(db.String(50), nullable=True)
    performed_by = db.Column(db.String(64), nullable=False)
    details = db.Column(db.String(255), nullable=True)