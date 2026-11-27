import urllib3
import requests
from datetime import datetime, timedelta
from app.models import SystemSetting

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiAnalyzerService:
    def __init__(self):
        self.enabled = SystemSetting.get("FAZ_ENABLED", "false").lower() == "true"
        self.base_url = SystemSetting.get("FAZ_URL", "").rstrip("/")
        self.api_token = SystemSetting.get("FAZ_API_TOKEN", "")
        self.adom = SystemSetting.get("FAZ_ADOM", "root") or "root"
        self.verify_ssl = SystemSetting.get("FAZ_VERIFY_SSL", "false").lower() == "true"

    @property
    def rpc_url(self) -> str:
        return f"{self.base_url}/jsonrpc"

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}",
        }

    def _post_rpc(self, payload: dict, timeout: int = 15) -> dict:
        if not self.base_url or not self.api_token:
            raise ValueError("URL ou API Token do FortiAnalyzer não configurados.")

        resp = requests.post(
            self.rpc_url,
            json=payload,
            headers=self._headers(),
            verify=self.verify_ssl,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        result = data.get("result")
        if isinstance(result, list) and result:
            status = result[0].get("status", {})
            if status.get("code", 0) != 0:
                raise RuntimeError(f"FAZ API Error ({status.get('code')}): {status.get('message')}")
        elif isinstance(result, dict):
            status = result.get("status", {})
            if status.get("code", 0) != 0:
                raise RuntimeError(f"FAZ API Error ({status.get('code')}): {status.get('message')}")

        return data

    def test_connection(self) -> tuple[bool, str]:
        """Valida URL, certificado e Bearer Token consultando o status do FAZ."""
        try:
            payload = {
                "id": 1,
                "method": "get",
                "params": [{"url": "/sys/status"}],
            }
            data = self._post_rpc(payload, timeout=10)
            info = data.get("result", [{}])[0].get("data", {})
            hostname = info.get("Hostname", "FortiAnalyzer")
            version = info.get("Version", "")
            return True, f"Conectado com sucesso: {hostname} ({version})"
        except Exception as exc:
            return False, str(exc)

    def get_vpn_usage_summary(self, usernames: list[str], lookback_days: int = 30) -> dict[str, dict]:
        """
        Consulta logs de eventos VPN no FortiAnalyzer e retorna um dicionário indexado por username:
        {
            "joao.silva": {
                "last_seen": datetime | None,
                "total_seconds": int,
                "is_online": bool
            }
        }
        """
        if not self.enabled or not usernames or not self.base_url or not self.api_token:
            return {}

        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=lookback_days)

        clean_users = [u.strip().lower() for u in usernames if u.strip()]
        user_filter = " or ".join([f'user=="{u}"' for u in clean_users])
        log_filter = f'subtype=="vpn" and ({user_filter})'

        start_payload = {
            "id": 1,
            "method": "add",
            "params": [
                {
                    "url": f"/logview/adom/{self.adom}/logsearch",
                    "apiver": 3,
                    "logtype": "event",
                    "filter": log_filter,
                    "time-range": {
                        "start": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "end": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    },
                    "limit": 1000,
                }
            ],
        }

        search_resp = self._post_rpc(start_payload, timeout=20)
        tid = search_resp.get("result", {}).get("tid")
        if not tid:
            return {}

        fetch_payload = {
            "id": 2,
            "method": "get",
            "params": [
                {
                    "url": f"/logview/adom/{self.adom}/logsearch/{tid}",
                    "apiver": 3,
                    "limit": 1000,
                    "offset": 0,
                }
            ],
        }
        logs_resp = self._post_rpc(fetch_payload, timeout=20)
        logs = logs_resp.get("result", {}).get("data", [])

        summary = {
            u: {"last_seen": None, "total_seconds": 0, "is_online": False, "_latest_ts": None}
            for u in clean_users
        }

        up_actions = {"tunnel-up", "ssl-login-ok", "ipsec-phase2-up"}
        down_actions = {"tunnel-down", "ssl-exit", "ssl-logout", "delete-sa"}

        for entry in logs:
            user = (entry.get("user") or entry.get("xauthuser") or "").strip().lower()
            if user not in summary:
                continue

            action = (entry.get("action") or "").strip().lower()
            date_str = entry.get("date", "")
            time_str = entry.get("time", "")

            event_dt = None
            if date_str and time_str:
                try:
                    event_dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            if action in down_actions:
                try:
                    summary[user]["total_seconds"] += int(entry.get("duration", 0))
                except (ValueError, TypeError):
                    pass

            if event_dt:
                if summary[user]["last_seen"] is None or event_dt > summary[user]["last_seen"]:
                    summary[user]["last_seen"] = event_dt

                if summary[user]["_latest_ts"] is None or event_dt >= summary[user]["_latest_ts"]:
                    if action in up_actions:
                        summary[user]["_latest_ts"] = event_dt
                        summary[user]["is_online"] = True
                    elif action in down_actions:
                        summary[user]["_latest_ts"] = event_dt
                        summary[user]["is_online"] = False

        cutoff = datetime.now() - timedelta(hours=14)
        for u, info in summary.items():
            if info["is_online"] and info["_latest_ts"] and info["_latest_ts"] < cutoff:
                info["is_online"] = False
            info.pop("_latest_ts", None)

        return summary