"""Tests for config.schema — Pydantic models for the persisted config.

These models are the schema boundary: everything the Settings page saves
flows through here and everything the runtime reads comes back out. We
check:
  - Defaults match what the docs + scheduler expect (e.g. opnsense poll
    defaults to 60s, firewalla to 120s).
  - `.masked()` redacts secrets (so audit logs + API responses can't
    accidentally surface a token).
  - poll_interval_seconds bounds are enforced by Field(ge/le).
"""
from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from config.schema import (
    ConfigRoot,
    ElasticsearchConfig,
    FirewallaConfig,
    OllamaConfig,
    OpenVASConfig,
    OPNsenseConfig,
    SchedulerConfig,
    UniFiConfig,
)


class TestDefaults:
    def test_root_defaults_carry_every_section(self):
        # Every integration section should exist on the root by default
        # so the Settings UI never has to deal with a None sub-object.
        root = ConfigRoot()
        assert root.version == 1
        assert root.setup_complete is False
        for attr in (
            "unifi", "opnsense", "firewalla", "elasticsearch",
            "openvas", "scheduler", "proxy", "claude", "ollama",
        ):
            assert getattr(root, attr) is not None

    def test_opnsense_default_poll_is_60_seconds(self):
        # Contract with the scheduler: opnsense_poll registers on this
        # interval. Changing this default without updating the scheduler
        # tests and CHANGELOG would be a silent behavior change.
        assert OPNsenseConfig().poll_interval_seconds == 60

    def test_firewalla_default_poll_is_120_seconds(self):
        assert FirewallaConfig().poll_interval_seconds == 120

    def test_firewalla_defaults_to_msp_mode(self):
        # Local mode is experimental; MSP is supported. Default path
        # must not shepherd users into the untested route.
        assert FirewallaConfig().mode == "msp"
        assert FirewallaConfig().alarms_enabled is True

    def test_opnsense_disabled_by_default(self):
        # Gateways are opt-in — running without an OPNsense box shouldn't
        # spin up a failing poll job at startup.
        assert OPNsenseConfig().enabled is False
        assert FirewallaConfig().enabled is False


class TestMasked:
    """Every config section with a secret must redact it in masked()
    so audit logs / API responses never leak the plaintext."""

    def test_opnsense_masked_hides_secret(self):
        c = OPNsenseConfig(
            enabled=True,
            url="https://10.0.0.1",
            api_key="k" * 60,
            api_secret=SecretStr("super-secret-value"),
        )
        m = c.masked()
        assert m["api_key"] == "k" * 60   # key is semi-public, fine to show
        assert m["api_secret"] == "••••••"
        assert "super-secret-value" not in str(m)

    def test_opnsense_masked_empty_secret_shows_empty(self):
        # When no secret is set, the mask should indicate empty, not
        # show bullets that'd suggest "there's something here".
        m = OPNsenseConfig().masked()
        assert m["api_secret"] == ""

    def test_firewalla_masked_hides_both_token_fields(self):
        c = FirewallaConfig(
            enabled=True,
            mode="msp",
            msp_domain="acme.firewalla.net",
            msp_token=SecretStr("pat_abc123"),
            local_token=SecretStr("fireguard_def456"),
        )
        m = c.masked()
        assert m["msp_token"] == "••••••"
        assert m["local_token"] == "••••••"
        assert "pat_abc123" not in str(m)
        assert "fireguard_def456" not in str(m)

    def test_ollama_masked_hides_api_key(self):
        c = OllamaConfig(enabled=True, api_key=SecretStr("sk-ollama-xyz"))
        m = c.masked()
        assert m["api_key"] == "••••••"
        assert "sk-ollama-xyz" not in str(m)

    def test_openvas_masked_hides_password(self):
        c = OpenVASConfig(password=SecretStr("rotated-random-secret"))
        m = c.masked()
        assert m["password"] == "••••••"
        assert "rotated-random-secret" not in str(m)

    def test_unifi_masked_hides_password(self):
        c = UniFiConfig(password=SecretStr("unifi-pw"))
        m = c.masked()
        assert m["password"] == "••••••"
        assert "unifi-pw" not in str(m)

    def test_elasticsearch_masked_hides_password(self):
        c = ElasticsearchConfig(password=SecretStr("elastic-pw"))
        m = c.masked()
        assert m["password"] == "••••••"

    def test_root_masked_walks_all_sections(self):
        root = ConfigRoot(
            opnsense=OPNsenseConfig(api_secret=SecretStr("osecret")),
            firewalla=FirewallaConfig(msp_token=SecretStr("mtoken")),
            unifi=UniFiConfig(password=SecretStr("upass")),
            openvas=OpenVASConfig(password=SecretStr("vpass")),
            ollama=OllamaConfig(api_key=SecretStr("okey")),
            elasticsearch=ElasticsearchConfig(password=SecretStr("epass")),
        )
        m = root.masked()
        # Spot-check the recursive redaction
        serialised = str(m)
        for plaintext in ("osecret", "mtoken", "upass", "vpass", "okey", "epass"):
            assert plaintext not in serialised, f"{plaintext!r} leaked through masked()"


class TestBounds:
    """Field(ge=..., le=...) bounds on intervals — anything outside them
    is a config error, not a silent cap at read time."""

    def test_opnsense_poll_floor(self):
        with pytest.raises(ValidationError):
            OPNsenseConfig(poll_interval_seconds=5)  # below ge=15

    def test_opnsense_poll_ceiling(self):
        with pytest.raises(ValidationError):
            OPNsenseConfig(poll_interval_seconds=10_000)  # above le=3600

    def test_firewalla_poll_floor(self):
        with pytest.raises(ValidationError):
            FirewallaConfig(poll_interval_seconds=10)  # below ge=30

    def test_firewalla_poll_ceiling(self):
        with pytest.raises(ValidationError):
            FirewallaConfig(poll_interval_seconds=99_999)

    def test_scheduler_nmap_bounds(self):
        with pytest.raises(ValidationError):
            SchedulerConfig(nmap_interval_minutes=0)
        with pytest.raises(ValidationError):
            SchedulerConfig(nmap_interval_minutes=10_000)

    def test_ollama_schedule_hour_bounds(self):
        with pytest.raises(ValidationError):
            OllamaConfig(daily_schedule_hour_utc=24)
        with pytest.raises(ValidationError):
            OllamaConfig(daily_schedule_hour_utc=-1)


class TestLiterals:
    def test_firewalla_mode_literal(self):
        # Literal["msp", "local"] — anything else must fail validation.
        with pytest.raises(ValidationError):
            FirewallaConfig(mode="cloud")  # type: ignore[arg-type]

    def test_proxy_cert_type_literal(self):
        from config.schema import ProxyConfig
        with pytest.raises(ValidationError):
            ProxyConfig(cert_type="acme")  # type: ignore[arg-type]
