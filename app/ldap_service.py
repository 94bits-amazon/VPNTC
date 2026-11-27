import ssl
from ldap3 import Server, Connection, ALL, Tls, MODIFY_ADD, MODIFY_DELETE
from ldap3.utils.conv import escape_filter_chars
from app.models import SystemSetting, VpnProfile


class LdapService:
    def __init__(self):
        self.server_uri = SystemSetting.get("LDAP_SERVER", "")
        self.use_ssl = SystemSetting.get("LDAP_USE_SSL", "true").lower() == "true"
        self.validate_cert = SystemSetting.get("LDAP_VALIDATE_CERT", "false").lower() == "true"
        self.base_dn = SystemSetting.get("LDAP_BASE_DN", "")
        self.user_search_base = SystemSetting.get("LDAP_USER_SEARCH_BASE", "") or self.base_dn
        self.group_search_base = SystemSetting.get("LDAP_GROUP_SEARCH_BASE", "") or self.base_dn
        self.bind_dn = SystemSetting.get("LDAP_BIND_DN", "")
        self.bind_password = SystemSetting.get("LDAP_BIND_PASSWORD", "")

    def _get_connection(self) -> Connection:
        if not self.server_uri or not self.bind_dn:
            raise ValueError("Configurações de servidor LDAP ou conta de serviço não preenchidas.")

        tls_config = None
        if self.use_ssl:
            cert_req = ssl.CERT_REQUIRED if self.validate_cert else ssl.CERT_NONE
            tls_config = Tls(validate=cert_req)

        server = Server(self.server_uri, use_ssl=self.use_ssl, tls=tls_config, get_info=ALL)
        return Connection(
            server,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True,
            raise_exceptions=True,
        )

    def test_connection(self) -> tuple[bool, str]:
        """Testa o bind LDAPS com as credenciais atuais."""
        try:
            with self._get_connection() as conn:
                return True, f"Conectado com sucesso em {conn.server.host}"
        except Exception as exc:
            return False, str(exc)

    def search_users(self, query: str, limit: int = 15) -> list[dict]:
        """Busca usuários ativos no AD e indica a quais perfis de VPN cadastrados já pertencem."""
        safe_q = escape_filter_chars(query.strip())
        if not safe_q:
            return []

        search_filter = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(|(sAMAccountName=*{safe_q}*)(displayName=*{safe_q}*)(mail=*{safe_q}*)))"
        )

        # Carrega os perfis ativos cadastrados no banco para exibir tags no autocomplete
        active_profiles = VpnProfile.query.filter_by(active=True).all()
        dn_to_profile = {p.group_dn.lower(): p.name for p in active_profiles}

        with self._get_connection() as conn:
            conn.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                attributes=["sAMAccountName", "displayName", "department", "distinguishedName", "memberOf"],
                size_limit=limit,
            )
            results = []
            for entry in conn.entries:
                member_of = [str(g).lower() for g in entry.memberOf] if "memberOf" in entry else []
                current_vpns = [
                    dn_to_profile[g_dn] for g_dn in member_of if g_dn in dn_to_profile
                ]
                results.append({
                    "sam_account_name": str(entry.sAMAccountName),
                    "display_name": str(entry.displayName) if "displayName" in entry else str(entry.sAMAccountName),
                    "department": str(entry.department) if "department" in entry else "",
                    "user_dn": str(entry.distinguishedName),
                    "current_vpns": current_vpns,
                })
            return results

    def search_groups(self, query: str, limit: int = 15) -> list[dict]:
        """Busca grupos no AD para cadastro dinâmico na tela /config."""
        safe_q = escape_filter_chars(query.strip())
        if not safe_q:
            return []

        search_filter = f"(&(objectClass=group)(|(cn=*{safe_q}*)(description=*{safe_q}*)))"

        with self._get_connection() as conn:
            conn.search(
                search_base=self.group_search_base,
                search_filter=search_filter,
                attributes=["cn", "distinguishedName", "description"],
                size_limit=limit,
            )
            return [
                {
                    "cn": str(entry.cn),
                    "group_dn": str(entry.distinguishedName),
                    "description": str(entry.description) if "description" in entry else "",
                }
                for entry in conn.entries
            ]

    def add_user_to_group(self, user_dn: str, group_dn: str) -> None:
        if not group_dn:
            raise ValueError("DN do grupo de destino não informado.")

        with self._get_connection() as conn:
            conn.search(
                search_base=group_dn,
                search_filter=f"(member={escape_filter_chars(user_dn)})",
                attributes=["cn"],
            )
            if not conn.entries:
                conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> None:
        if not group_dn:
            raise ValueError("DN do grupo de destino não informado.")

        with self._get_connection() as conn:
            conn.search(
                search_base=group_dn,
                search_filter=f"(member={escape_filter_chars(user_dn)})",
                attributes=["cn"],
            )
            if conn.entries:
                conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})