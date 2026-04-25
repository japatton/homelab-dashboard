from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import SecretStr

from .schema import (
    ConfigRoot,
)

CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "/data/config.yml"))


def _load_from_env(config: ConfigRoot) -> ConfigRoot:
    """Populate config fields from environment variables.

    Caller is expected to gate by `only on first boot` (see ConfigManager.load)
    — once the user has saved the config via the Settings UI, the persisted
    values win, otherwise env vars in docker-compose silently revert Settings
    changes on every restart. The OpenVAS host field used to do exactly that
    before this was reworked; see docker-compose.yml's OPENVAS_HOST comment."""

    def _env(key: str, default: str = "") -> str:
        return os.getenv(key, default)

    if _env("UNIFI_URL"):
        config.unifi.url = _env("UNIFI_URL")
    if _env("UNIFI_USER"):
        config.unifi.user = _env("UNIFI_USER")
    if _env("UNIFI_PASS"):
        config.unifi.password = SecretStr(_env("UNIFI_PASS"))
    if _env("UNIFI_SITE"):
        config.unifi.site = _env("UNIFI_SITE")

    if _env("ES_HOST"):
        config.elasticsearch.host = _env("ES_HOST")
    if _env("ES_PORT"):
        config.elasticsearch.port = int(_env("ES_PORT", "9200"))
    if _env("ES_USER"):
        config.elasticsearch.user = _env("ES_USER")
    if _env("ES_PASS"):
        config.elasticsearch.password = SecretStr(_env("ES_PASS"))

    if _env("OPENVAS_HOST"):
        config.openvas.host = _env("OPENVAS_HOST")
    if _env("OPENVAS_PORT"):
        config.openvas.port = int(_env("OPENVAS_PORT", "9390"))
    if _env("OPENVAS_USER"):
        config.openvas.user = _env("OPENVAS_USER")
    if _env("OPENVAS_PASS"):
        config.openvas.password = SecretStr(_env("OPENVAS_PASS"))

    if _env("DOMAIN_MODE"):
        config.proxy.mode = _env("DOMAIN_MODE", "ip")  # type: ignore[assignment]
    if _env("EXTERNAL_HOST"):
        config.proxy.external_host = _env("EXTERNAL_HOST", "localhost")
    if _env("CERT_TYPE"):
        config.proxy.cert_type = _env("CERT_TYPE", "none")  # type: ignore[assignment]

    if _env("CLAUDE_ENABLED"):
        config.claude.enabled = _env("CLAUDE_ENABLED", "false").lower() == "true"

    if _env("NMAP_INTERVAL_MINUTES"):
        config.scheduler.nmap_interval_minutes = int(
            _env("NMAP_INTERVAL_MINUTES", "15")
        )
    if _env("UNIFI_POLL_INTERVAL_SECONDS"):
        config.scheduler.unifi_poll_interval_seconds = int(
            _env("UNIFI_POLL_INTERVAL_SECONDS", "30")
        )
    if _env("OPENVAS_INTERVAL_HOURS"):
        config.scheduler.openvas_interval_hours = int(
            _env("OPENVAS_INTERVAL_HOURS", "24")
        )

    return config


def _migrate(data: dict) -> dict:
    version = data.get("version", 0)
    if version < 1:
        data["version"] = 1
        data.setdefault("setup_complete", False)
    return data


class ConfigManager:
    def __init__(self, path: Path = CONFIG_PATH):
        self._path = path
        self._config: Optional[ConfigRoot] = None

    def load(self) -> ConfigRoot:
        # "First boot" = no persisted yaml yet. Only then do we seed from
        # env, giving docker-compose users a one-time path to pre-populate
        # connection details without having to click through the wizard.
        # Once the yaml exists, user choices (from Settings) are authoritative —
        # env is ignored. That keeps the Settings page from silently reverting
        # on restart (see OPENVAS_HOST incident in docker-compose.yml).
        is_first_boot = not self._path.exists()
        if is_first_boot:
            self._config = ConfigRoot()
            self._config = _load_from_env(self._config)
        else:
            raw = yaml.safe_load(self._path.read_text()) or {}
            raw = _migrate(raw)
            self._config = ConfigRoot.model_validate(raw)
        return self._config

    def get(self) -> ConfigRoot:
        if self._config is None:
            return self.load()
        return self._config

    def save(self, config: Optional[ConfigRoot] = None) -> None:
        cfg = config or self._config
        if cfg is None:
            return

        self._config = cfg
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Serialise SecretStr fields as plain strings for YAML storage
        data = cfg.model_dump()
        self._secret_to_str(data)

        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True)
        tmp.replace(self._path)

    def _secret_to_str(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(value, "get_secret_value"):
                data[key] = value.get_secret_value()
            elif isinstance(value, dict):
                self._secret_to_str(value)

    def is_setup_complete(self) -> bool:
        return self.get().setup_complete

    def update_scheduler(self, **kwargs) -> None:
        cfg = self.get()
        for k, v in kwargs.items():
            setattr(cfg.scheduler, k, v)
        self.save(cfg)


@functools.lru_cache(maxsize=1)
def get_config_manager() -> ConfigManager:
    return ConfigManager()
