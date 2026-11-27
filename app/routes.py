import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app.models import db, VpnAccess, VpnProfile, AuditLog, SystemSetting
from app.ldap_service import LdapService
from app.faz_service import FortiAnalyzerService

bp = Blueprint("main", __name__)


def get_current_operator() -> str:
    remote_user = request.headers.get("Remote-User", "").strip()
    if remote_user:
        return remote_user
    return os.getenv("DEV_MOCK_USER", "").strip() or "tiago.oliva"


def is_admin_operator() -> bool:
    """Verifica se o usuário pertence a algum grupo de Admin configurado (ou está em modo dev)."""
    if os.getenv("DEV_MOCK_USER", "").strip() or not request.headers.get("Remote-User"):
        return True
    admin_groups_raw = SystemSetting.get("ADMIN_GROUPS", "")
    if not admin_groups_raw.strip():
        return True
    allowed = {g.strip().lower() for g in admin_groups_raw.split(",") if g.strip()}
    user_groups = {g.strip().lower() for g in request.headers.get("Remote-Groups", "").split(",") if g.strip()}
    return bool(allowed & user_groups)


@bp.context_processor
def inject_operator():
    return {
        "current_operator": get_current_operator(),
        "operator_name": request.headers.get("Remote-Name", get_current_operator()),
        "is_admin": is_admin_operator(),
    }


@bp.route("/")
def dashboard():
    profiles = VpnProfile.query.filter_by(active=True).order_by(VpnProfile.name.asc()).all()
    active_list = (
        VpnAccess.query.filter_by(status="ACTIVE")
        .order_by(VpnAccess.expires_at.asc())
        .all()
    )
    expired_list = (
        VpnAccess.query.filter(VpnAccess.status.in_(["EXPIRED", "REVOKED"]))
        .order_by(VpnAccess.expires_at.desc())
        .limit(100)
        .all()
    )
    return render_template(
        "dashboard.html",
        profiles=profiles,
        active_list=active_list,
        expired_list=expired_list,
        faz_enabled=SystemSetting.get("FAZ_ENABLED", "false").lower() == "true",
    )


@bp.route("/api/search-users")
def search_users():
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify([])
    try:
        users = LdapService().search_users(q)
        return jsonify(users)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/api/search-groups")
def search_groups():
    if not is_admin_operator():
        return jsonify({"error": "Acesso negado"}), 403
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify([])
    try:
        groups = LdapService().search_groups(q)
        return jsonify(groups)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/grant", methods=["POST"])
def grant_access():
    operator = get_current_operator()
    sam_account_name = request.form.get("sam_account_name", "").strip()
    display_name = request.form.get("display_name", "").strip()
    department = request.form.get("department", "").strip()
    user_dn = request.form.get("user_dn", "").strip()
    profile_id = request.form.get("profile_id", type=int)
    ticket_number = request.form.get("ticket_number", "").strip()

    duration_mode = request.form.get("duration_days", "30")
    if duration_mode == "custom":
        duration_days = request.form.get("custom_days", type=int) or 0
    else:
        try:
            duration_days = int(duration_mode)
        except ValueError:
            duration_days = 0

    profile = VpnProfile.query.get(profile_id) if profile_id else None

    if not all([sam_account_name, user_dn, profile, ticket_number]) or duration_days < 1 or duration_days > 3650:
        flash("Preencha todos os campos corretamente (Colaborador, Perfil, Prazo entre 1 e 3650 dias e Chamado).", "danger")
        return redirect(url_for("main.dashboard"))

    now = datetime.now()
    expires_at = now + timedelta(days=duration_days)

    try:
        LdapService().add_user_to_group(user_dn, profile.group_dn)

        record = VpnAccess.query.filter_by(
            sam_account_name=sam_account_name,
            profile_id=profile.id,
        ).first()

        action_type = "GRANTED"
        if record:
            action_type = "RENEWED" if record.status != "ACTIVE" else "UPDATED"
            record.display_name = display_name or record.display_name
            record.department = department
            record.user_dn = user_dn
            record.duration_days = duration_days
            record.granted_at = now
            record.expires_at = expires_at
            record.status = "ACTIVE"
            record.last_ticket = ticket_number
            record.granted_by = operator
        else:
            record = VpnAccess(
                sam_account_name=sam_account_name,
                display_name=display_name or sam_account_name,
                department=department,
                user_dn=user_dn,
                profile_id=profile.id,
                duration_days=duration_days,
                granted_at=now,
                expires_at=expires_at,
                status="ACTIVE",
                last_ticket=ticket_number,
                granted_by=operator,
            )
            db.session.add(record)

        db.session.add(AuditLog(
            action=action_type,
            target_user=sam_account_name,
            target_name=display_name or sam_account_name,
            vpn_profile_name=profile.name,
            duration_days=duration_days,
            ticket_number=ticket_number,
            performed_by=operator,
            details=f"Acesso '{profile.name}' liberado por {duration_days} dia(s) (Ticket: {ticket_number}).",
        ))
        db.session.commit()
        flash(f"VPN '{profile.name}' liberada para {sam_account_name} por {duration_days} dia(s)!", "success")
    except Exception as exc:
        db.session.rollback()
        flash(f"Erro ao liberar acesso no AD: {exc}", "danger")

    return redirect(url_for("main.dashboard"))


@bp.route("/renew/<int:access_id>", methods=["POST"])
def renew_access(access_id: int):
    operator = get_current_operator()
    record = VpnAccess.query.get_or_404(access_id)
    ticket_number = request.form.get("ticket_number", "").strip()

    duration_mode = request.form.get("duration_days", "30")
    if duration_mode == "custom":
        duration_days = request.form.get("custom_days", type=int) or 0
    else:
        try:
            duration_days = int(duration_mode)
        except ValueError:
            duration_days = 0

    if not ticket_number or duration_days < 1 or duration_days > 3650:
        flash("Informe o número do chamado e um prazo válido (1 a 3650 dias).", "danger")
        return redirect(url_for("main.dashboard"))

    now = datetime.now()
    expires_at = now + timedelta(days=duration_days)

    try:
        LdapService().add_user_to_group(record.user_dn, record.profile.group_dn)

        record.duration_days = duration_days
        record.granted_at = now
        record.expires_at = expires_at
        record.status = "ACTIVE"
        record.last_ticket = ticket_number
        record.granted_by = operator

        db.session.add(AuditLog(
            action="RENEWED",
            target_user=record.sam_account_name,
            target_name=record.display_name,
            vpn_profile_name=record.profile.name,
            duration_days=duration_days,
            ticket_number=ticket_number,
            performed_by=operator,
            details=f"Acesso '{record.profile.name}' renovado por {duration_days} dia(s) (Ticket: {ticket_number}).",
        ))
        db.session.commit()
        flash(f"VPN '{record.profile.name}' de {record.sam_account_name} renovada por {duration_days} dia(s)!", "success")
    except Exception as exc:
        db.session.rollback()
        flash(f"Erro ao renovar acesso no AD: {exc}", "danger")

    return redirect(url_for("main.dashboard"))


@bp.route("/revoke/<int:access_id>", methods=["POST"])
def revoke_access(access_id: int):
    operator = get_current_operator()
    record = VpnAccess.query.get_or_404(access_id)
    reason = request.form.get("reason", "").strip() or "Revogação manual pelo painel"

    try:
        LdapService().remove_user_from_group(record.user_dn, record.profile.group_dn)

        record.status = "REVOKED"
        record.is_online_now = False
        record.expires_at = datetime.now()

        db.session.add(AuditLog(
            action="REVOKED_MANUAL",
            target_user=record.sam_account_name,
            target_name=record.display_name,
            vpn_profile_name=record.profile.name,
            duration_days=record.duration_days,
            ticket_number=record.last_ticket,
            performed_by=operator,
            details=reason,
        ))
        db.session.commit()
        flash(f"Acesso '{record.profile.name}' de {record.sam_account_name} revogado.", "warning")
    except Exception as exc:
        db.session.rollback()
        flash(f"Erro ao revogar acesso no AD: {exc}", "danger")

    return redirect(url_for("main.dashboard"))


@bp.route("/logs")
def logs():
    page = request.args.get("page", 1, type=int)
    user_filter = request.args.get("user", "").strip()

    query = AuditLog.query
    if user_filter:
        query = query.filter(AuditLog.target_user.ilike(f"%{user_filter}%"))

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=30, error_out=False)
    return render_template("logs.html", pagination=pagination, user_filter=user_filter)


@bp.route("/config", methods=["GET", "POST"])
def config():
    if not is_admin_operator():
        flash("Acesso restrito aos administradores de infraestrutura.", "danger")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        action = request.form.get("form_action")

        if action == "save_settings":
            SystemSetting.set("LDAP_SERVER", request.form.get("LDAP_SERVER", "").strip())
            SystemSetting.set("LDAP_USE_SSL", "true" if request.form.get("LDAP_USE_SSL") else "false")
            SystemSetting.set("LDAP_VALIDATE_CERT", "true" if request.form.get("LDAP_VALIDATE_CERT") else "false")
            SystemSetting.set("LDAP_BASE_DN", request.form.get("LDAP_BASE_DN", "").strip())
            SystemSetting.set("LDAP_USER_SEARCH_BASE", request.form.get("LDAP_USER_SEARCH_BASE", "").strip())
            SystemSetting.set("LDAP_GROUP_SEARCH_BASE", request.form.get("LDAP_GROUP_SEARCH_BASE", "").strip())
            SystemSetting.set("LDAP_BIND_DN", request.form.get("LDAP_BIND_DN", "").strip())
            SystemSetting.set("LDAP_BIND_PASSWORD", request.form.get("LDAP_BIND_PASSWORD", "").strip(), is_secret=True)
            SystemSetting.set("ADMIN_GROUPS", request.form.get("ADMIN_GROUPS", "").strip())
            SystemSetting.set("EXPIRATION_CHECK_INTERVAL_MINUTES", request.form.get("EXPIRATION_CHECK_INTERVAL_MINUTES", "15").strip())

            SystemSetting.set("FAZ_ENABLED", "true" if request.form.get("FAZ_ENABLED") else "false")
            SystemSetting.set("FAZ_URL", request.form.get("FAZ_URL", "").strip())
            SystemSetting.set("FAZ_ADOM", request.form.get("FAZ_ADOM", "root").strip())
            SystemSetting.set("FAZ_VERIFY_SSL", "true" if request.form.get("FAZ_VERIFY_SSL") else "false")
            SystemSetting.set("FAZ_API_TOKEN", request.form.get("FAZ_API_TOKEN", "").strip(), is_secret=True)

            db.session.add(AuditLog(
                action="CONFIG_UPDATED",
                target_user="SYSTEM",
                vpn_profile_name="-",
                performed_by=get_current_operator(),
                details="Configurações de AD / FortiAnalyzer / RBAC atualizadas.",
            ))
            db.session.commit()
            flash("Configurações salvas com sucesso!", "success")

        elif action == "add_profile":
            name = request.form.get("profile_name", "").strip()
            group_dn = request.form.get("profile_group_dn", "").strip()
            badge_color = request.form.get("badge_color", "primary").strip()
            if name and group_dn:
                db.session.add(VpnProfile(name=name, group_dn=group_dn, badge_color=badge_color, active=True))
                db.session.commit()
                flash(f"Perfil VPN '{name}' adicionado!", "success")

        elif action == "toggle_profile":
            pid = request.form.get("profile_id", type=int)
            prof = VpnProfile.query.get(pid)
            if prof:
                prof.active = not prof.active
                db.session.commit()
                flash(f"Perfil '{prof.name}' {'ativado' if prof.active else 'desativado'}.", "info")

        return redirect(url_for("main.config"))

    settings = {
        "LDAP_SERVER": SystemSetting.get("LDAP_SERVER", ""),
        "LDAP_USE_SSL": SystemSetting.get("LDAP_USE_SSL", "true"),
        "LDAP_VALIDATE_CERT": SystemSetting.get("LDAP_VALIDATE_CERT", "false"),
        "LDAP_BASE_DN": SystemSetting.get("LDAP_BASE_DN", ""),
        "LDAP_USER_SEARCH_BASE": SystemSetting.get("LDAP_USER_SEARCH_BASE", ""),
        "LDAP_GROUP_SEARCH_BASE": SystemSetting.get("LDAP_GROUP_SEARCH_BASE", ""),
        "LDAP_BIND_DN": SystemSetting.get("LDAP_BIND_DN", ""),
        "HAS_LDAP_PASS": bool(SystemSetting.get("LDAP_BIND_PASSWORD", "")),
        "ADMIN_GROUPS": SystemSetting.get("ADMIN_GROUPS", ""),
        "EXPIRATION_CHECK_INTERVAL_MINUTES": SystemSetting.get("EXPIRATION_CHECK_INTERVAL_MINUTES", "15"),
        "FAZ_ENABLED": SystemSetting.get("FAZ_ENABLED", "false"),
        "FAZ_URL": SystemSetting.get("FAZ_URL", ""),
        "FAZ_ADOM": SystemSetting.get("FAZ_ADOM", "root"),
        "FAZ_VERIFY_SSL": SystemSetting.get("FAZ_VERIFY_SSL", "false"),
        "HAS_FAZ_TOKEN": bool(SystemSetting.get("FAZ_API_TOKEN", "")),
    }
    profiles = VpnProfile.query.order_by(VpnProfile.name.asc()).all()
    return render_template("config.html", settings=settings, profiles=profiles)


@bp.route("/api/test-ldap", methods=["POST"])
def test_ldap():
    if not is_admin_operator():
        return jsonify({"ok": False, "message": "Acesso negado"}), 403
    ok, msg = LdapService().test_connection()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/api/test-faz", methods=["POST"])
def test_faz():
    if not is_admin_operator():
        return jsonify({"ok": False, "message": "Acesso negado"}), 403
    ok, msg = FortiAnalyzerService().test_connection()
    return jsonify({"ok": ok, "message": msg})