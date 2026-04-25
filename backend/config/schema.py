from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field, SecretStr, model_validator


class UniFiConfig(BaseModel):
    url: str = "https://192.168.1.1"
    user: str = ""
    password: SecretStr = SecretStr("")
    site: str = "default"
    verify_ssl: bool = False

    def masked(self) -> dict:
        return {
            "url": self.url,
            "user": self.user,
            "password": "••••••" if self.password.get_secret_value() else "",
            "site": self.site,
        }


class ElasticsearchConfig(BaseModel):
    host: str = ""
    port: int = 9200
    user: str = ""
    password: SecretStr = SecretStr("")
    index_prefix: str = "homelab"

    def masked(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": "••••••" if self.password.get_secret_value() else "",
            "index_prefix": self.index_prefix,
        }


class OPNsenseConfig(BaseModel):
    """OPNsense edge-gateway integration (single instance).

    OPNsense is a pure gateway — it gives us authoritative DHCP leases
    (real hostnames the DHCP server actually issued), a live ARP table,
    and optional Suricata IDS alerts. Everything flows through the same
    REST API, authenticated with a key/secret pair that the user creates
    per-user at System → Access → Users → (user) → API keys.

    `url` is the full base URL including scheme (e.g. https://10.0.0.1).
    `api_key` is the opaque 60+ char key and `api_secret` its secret
    half — together they act as HTTP Basic auth credentials.
    `verify_ssl` defaults to False because OPNsense ships with a self-
    signed cert out of the box and homelabs rarely replace it; flip to
    True if the user is running a real cert.
    `ids_enabled` toggles whether the poller queries Suricata alerts
    (extra endpoint, ignorable when the IDS isn't running).
    """
    enabled: bool = False
    url: str = ""
    api_key: str = ""
    api_secret: SecretStr = SecretStr("")
    verify_ssl: bool = False
    ids_enabled: bool = False
    # Poll cadence in seconds. DHCP/ARP is cheap so 60s is plenty — more
    # frequent than that just thrashes the firewall's console logs.
    poll_interval_seconds: int = Field(default=60, ge=15, le=3600)

    def masked(self) -> dict:
        return {
            "enabled": self.enabled,
            "url": self.url,
            "api_key": self.api_key,
            "api_secret": "••••••" if self.api_secret.get_secret_value() else "",
            "verify_ssl": self.verify_ssl,
            "ids_enabled": self.ids_enabled,
            "poll_interval_seconds": self.poll_interval_seconds,
        }


class FirewallaConfig(BaseModel):
    """Firewalla integration (single instance).

    Two modes:
      - "msp": cloud-mediated API at https://<msp_domain>/v2/ — the
        recommended path. User creates a Personal Access Token in the
        MSP portal (Account Settings → Create New Token). We send it
        as `Authorization: Token <pat>` on every request.
      - "local": direct HTTP to the box on port 8833 using a fireguard
        token. Experimental — the local API isn't officially documented
        and the token flow is janky. Use MSP unless you have a hard
        requirement to avoid the cloud.

    `msp_domain` is just the host (e.g. "mycompany.firewalla.net"); the
    scheme and /v2/ prefix are added by the client.
    `local_url` is the full base URL (http://<box_ip>:8833).
    """
    enabled: bool = False
    mode: Literal["msp", "local"] = "msp"
    # MSP-mode fields
    msp_domain: str = ""
    msp_token: SecretStr = SecretStr("")
    # Local-mode fields
    local_url: str = ""
    local_token: SecretStr = SecretStr("")
    verify_ssl: bool = False
    # Alarm polling is the most interesting signal; devices/flows are
    # extras. Kept here so the user can turn off the alarm fetch if
    # they're rate-limited.
    alarms_enabled: bool = True
    poll_interval_seconds: int = Field(default=120, ge=30, le=3600)

    def masked(self) -> dict:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "msp_domain": self.msp_domain,
            "msp_token": "••••••" if self.msp_token.get_secret_value() else "",
            "local_url": self.local_url,
            "local_token": "••••••" if self.local_token.get_secret_value() else "",
            "verify_ssl": self.verify_ssl,
            "alarms_enabled": self.alarms_enabled,
            "poll_interval_seconds": self.poll_interval_seconds,
        }


class OpenVASConfig(BaseModel):
    # Use the pinned container_name rather than the compose service name.
    # Both resolve inside `homelab-net` when the stack is brought up by
    # compose, BUT after our in-UI reset flow recreates the container via
    # the docker SDK (services/openvas_reset.py), only the container_name
    # alias survives — compose's service-name alias is a compose-managed
    # thing we can't re-attach from python-docker. Defaulting to the name
    # that works in both cases keeps the scheduled scan reachable across a
    # reset. See docker-compose.yml (`container_name: homelab-openvas`).
    host: str = "homelab-openvas"
    port: int = 9390
    user: str = "admin"
    password: SecretStr = SecretStr("")

    def masked(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": "••••••" if self.password.get_secret_value() else "",
        }


class SchedulerConfig(BaseModel):
    nmap_interval_minutes: int = Field(default=15, ge=1, le=1440)
    unifi_poll_interval_seconds: int = Field(default=30, ge=5, le=3600)
    openvas_interval_hours: int = Field(default=24, ge=1, le=168)
    # OPNsense + Firewalla intervals live on their own config sections
    # (OPNsenseConfig.poll_interval_seconds, FirewallaConfig.poll_interval_seconds)
    # so each integration owns its own polling knob. SchedulerConfig is
    # kept to the "core" jobs so the existing Settings UI doesn't bloat.


class ProxyConfig(BaseModel):
    mode: Literal["ip", "domain"] = "ip"
    external_host: str = "localhost"
    cert_type: Literal["none", "selfsigned", "letsencrypt"] = "none"
    letsencrypt_email: str = ""


class ClaudeConfig(BaseModel):
    enabled: bool = False
    sandbox_path: str = "./integrations"
    allowed_tools: list[str] = ["Edit", "Write"]


class OllamaConfig(BaseModel):
    """Local AI analysis via Ollama (or OpenWebUI proxy).

    host/port point at the OpenAI-compatible endpoint — that's
    :11434/v1 for direct Ollama or OpenWebUI's configured port.
    Leave api_key blank for vanilla Ollama; OpenWebUI may require one.
    """
    enabled: bool = False
    host: str = ""
    port: int = 11434
    model: str = "gemma3:4b"
    api_key: SecretStr = SecretStr("")
    daily_schedule_hour_utc: int = Field(default=6, ge=0, le=23)

    def masked(self) -> dict:
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "model": self.model,
            "api_key": "••••••" if self.api_key.get_secret_value() else "",
            "daily_schedule_hour_utc": self.daily_schedule_hour_utc,
        }


class ConfigRoot(BaseModel):
    version: int = 1
    setup_complete: bool = False
    unifi: UniFiConfig = Field(default_factory=UniFiConfig)
    opnsense: OPNsenseConfig = Field(default_factory=OPNsenseConfig)
    firewalla: FirewallaConfig = Field(default_factory=FirewallaConfig)
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    openvas: OpenVASConfig = Field(default_factory=OpenVASConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    claude: ClaudeConfig = Field(default_factory=ClaudeConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)

    def masked(self) -> dict:
        return {
            "version": self.version,
            "setup_complete": self.setup_complete,
            "unifi": self.unifi.masked(),
            "opnsense": self.opnsense.masked(),
            "firewalla": self.firewalla.masked(),
            "elasticsearch": self.elasticsearch.masked(),
            "openvas": self.openvas.masked(),
            "scheduler": self.scheduler.model_dump(),
            "proxy": self.proxy.model_dump(),
            "claude": self.claude.model_dump(),
            "ollama": self.ollama.masked(),
        }
