import logging
from datetime import datetime
from app.models import db, VpnAccess, AuditLog
from app.ldap_service import LdapService
from app.faz_service import FortiAnalyzerService

logger = logging.getLogger(__name__)


def sync_and_expire_vpns(app):
    """
    Job periódico que:
    1. Revoga no AD os acessos VPN vencidos (usando o group_dn dinâmico do VpnProfile).
    2. Atualiza a telemetria de uso (status online, última conexão, tempo total) via FortiAnalyzer.
    """
    with app.app_context():
        now = datetime.now()

        # 1. Expiração automática de acessos vencidos
        expired_records = VpnAccess.query.filter(
            VpnAccess.status == "ACTIVE",
            VpnAccess.expires_at <= now,
        ).all()

        if expired_records:
            ldap = LdapService()
            for record in expired_records:
                try:
                    group_dn = record.profile.group_dn
                    profile_name = record.profile.name

                    ldap.remove_user_from_group(record.user_dn, group_dn)

                    record.status = "EXPIRED"
                    record.is_online_now = False

                    log_entry = AuditLog(
                        action="EXPIRED_AUTO",
                        target_user=record.sam_account_name,
                        target_name=record.display_name,
                        vpn_profile_name=profile_name,
                        duration_days=record.duration_days,
                        ticket_number=record.last_ticket,
                        performed_by="SYSTEM",
                        details=f"Acesso '{profile_name}' expirado automaticamente após {record.duration_days} dia(s).",
                    )
                    db.session.add(log_entry)
                    db.session.commit()
                    logger.info(
                        f"[VPNTC] Acesso '{profile_name}' expirado e removido do AD para {record.sam_account_name}."
                    )
                except Exception as exc:
                    db.session.rollback()
                    logger.error(
                        f"[VPNTC] Falha ao remover {record.sam_account_name} ({record.profile.name}) do AD: {exc}"
                    )

        # 2. Sincronização de telemetria com o FortiAnalyzer (para os registros que permanecem ativos)
        active_records = VpnAccess.query.filter_by(status="ACTIVE").all()
        if not active_records:
            return

        faz = FortiAnalyzerService()
        if not faz.enabled:
            return

        try:
            usernames = list({r.sam_account_name for r in active_records})
            usage_map = faz.get_vpn_usage_summary(usernames, lookback_days=30)

            for record in active_records:
                info = usage_map.get(record.sam_account_name.lower())
                if info:
                    record.last_faz_seen = info["last_seen"]
                    record.total_faz_seconds = info["total_seconds"]
                    record.is_online_now = info["is_online"]

            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning(f"[VPNTC] Falha ao consultar telemetria no FortiAnalyzer: {exc}")