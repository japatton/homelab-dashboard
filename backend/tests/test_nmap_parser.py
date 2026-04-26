"""Tests for integrations.nmap.

Two surfaces:

  1. _parse_xml — turns `nmap -oX -` output into our Device/Service
     shape. We don't shell out to nmap in tests; we feed hand-built
     XML fixtures and verify the parser extracts what we promise.

  2. validate_targets (F-003) — gates the input list before it reaches
     Nmap argv. The flag-injection family (`-iL /etc/shadow`, `--script`,
     `-oN`) all start with `-`; the regex also rejects shapes that
     wouldn't be legitimate IPv4/CIDR/hostname inputs.
"""

from __future__ import annotations

import pytest

from integrations.nmap import _parse_xml, TargetValidationError, validate_targets


_XML_BASIC = """<?xml version="1.0"?>
<nmaprun start="1700000000">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <hostnames>
      <hostname name="raspberry.lan" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Debian"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name=""/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="96"/>
    </os>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
  <runstats><finished time="1700000123" elapsed="12.3"/></runstats>
</nmaprun>
"""


def test_parses_up_host_with_ports():
    r = _parse_xml(_XML_BASIC, "nmap -oX - -T4 -sV 192.168.1.0/24")
    assert len(r.hosts) == 1  # down host skipped
    h = r.hosts[0]
    assert h.ip == "192.168.1.50"
    assert h.mac == "AA:BB:CC:DD:EE:FF"
    assert h.hostname == "raspberry.lan"
    assert h.os_guess == "Linux 5.15"


def test_only_open_ports_pass_through():
    r = _parse_xml(_XML_BASIC, "cmd")
    ports = {p.port for p in r.hosts[0].ports}
    assert ports == {22, 80}  # 9999 closed, dropped


def test_service_version_concat():
    # product + version + extrainfo get glued into a single display string.
    r = _parse_xml(_XML_BASIC, "cmd")
    ssh_port = next(p for p in r.hosts[0].ports if p.port == 22)
    assert "OpenSSH" in ssh_port.version
    assert "9.2p1" in ssh_port.version
    assert "Debian" in ssh_port.version


def test_scan_duration_captured():
    r = _parse_xml(_XML_BASIC, "cmd")
    assert r.scan_duration_seconds == 12.3


def test_host_without_ipv4_skipped():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="2001:db8::1" addrtype="ipv6"/>
      </host>
      <runstats><finished time="0" elapsed="0"/></runstats>
    </nmaprun>
    """
    r = _parse_xml(xml, "cmd")
    assert r.hosts == []


def test_empty_xml_returns_empty_result():
    xml = """<?xml version="1.0"?>
    <nmaprun><runstats><finished time="0" elapsed="0"/></runstats></nmaprun>
    """
    r = _parse_xml(xml, "cmd")
    assert r.hosts == []
    assert r.command == "cmd"


def test_malformed_xml_returns_empty_result_not_raise():
    # Parser must never bubble an ET.ParseError up — a garbage nmap
    # response should log and return empty, not crash the scan job.
    r = _parse_xml("<not-valid-xml", "cmd")
    assert r.hosts == []


def test_open_filtered_state_is_included():
    # open|filtered happens on UDP scans — we want to include these as
    # open-ish so the service enrichment still fires.
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="udp" portid="53">
            <state state="open|filtered"/>
            <service name="domain"/>
          </port>
        </ports>
      </host>
      <runstats><finished time="0" elapsed="0"/></runstats>
    </nmaprun>
    """
    r = _parse_xml(xml, "cmd")
    assert len(r.hosts[0].ports) == 1
    assert r.hosts[0].ports[0].port == 53
    assert r.hosts[0].ports[0].state == "open|filtered"


# ─── validate_targets (F-003) ──────────────────────────────────────────


class TestValidateTargets:
    """F-003: targets reach Nmap argv positionally; anything starting
    with `-` becomes a flag. validate_targets is the API-boundary
    gate that rejects flag-shaped strings before they get there."""

    # ---- accept ----

    @pytest.mark.parametrize(
        "ok",
        [
            ["192.168.1.50"],
            ["192.168.1.0/24"],
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            ["192.168.1.10-50"],
            ["raspberry.lan"],
            ["my-server.home.arpa"],
            ["a.b.c"],  # short hostname is fine
            # 64 entries — exactly at the cap, must succeed
            [f"10.0.0.{i}" for i in range(1, 65)],
        ],
    )
    def test_accepts_legitimate_targets(self, ok: list[str]):
        validate_targets(ok)  # must not raise

    # ---- reject: flag injection ----

    @pytest.mark.parametrize(
        "bad",
        [
            "-iL",  # read-targets-from-file
            "--script",  # NSE script load
            "-oN",  # write nmap-text output
            "-oX",  # write nmap-xml output
            "-A",  # aggressive scan
            "--script-args=cmd=id",
            "-",
            "--",
            "-iL=/etc/shadow",
        ],
    )
    def test_rejects_leading_dash(self, bad: str):
        with pytest.raises(TargetValidationError):
            validate_targets([bad])

    def test_rejects_mixed_legitimate_and_flag(self):
        # Even with legitimate targets present, a single flag-shaped
        # entry kills the whole list.
        with pytest.raises(TargetValidationError):
            validate_targets(["10.0.0.1", "-iL", "10.0.0.2"])

    # ---- reject: malformed shapes ----

    @pytest.mark.parametrize(
        "bad",
        [
            # Shell metachar in a single entry — exec list-form is safe
            # from shell injection regardless, but the validator catches
            # the typo early.
            "10.0.0.1; rm -rf /",
            # Space in a single entry: a comma was probably meant.
            "10.0.0.1 10.0.0.2",
            # Newline: would arrive as one argv but indicates a
            # copy-paste mistake or active injection attempt.
            "10.0.0.1\nfile.txt",
            # Whitespace-only — strip() reduces to empty, rejected.
            "  ",
        ],
    )
    def test_rejects_malformed_shape(self, bad: str):
        with pytest.raises(TargetValidationError):
            validate_targets([bad])

    def test_intentionally_does_not_validate_ip_arithmetic(self):
        # The validator's job is to gate flag-injection, not to do IP
        # arithmetic. "192.168.1" parses as a 3-label DNS hostname per
        # RFC 1035 (all-digit labels are legal); "999.999.999.999"
        # matches the IPv4 shape but each octet > 255. Both are accepted
        # at this layer and would be rejected by Nmap itself at runtime.
        # Documenting the deliberate choice so a future "tighten this"
        # PR has rationale.
        validate_targets(["192.168.1"])
        validate_targets(["999.999.999.999"])

    # ---- reject: list-level problems ----

    def test_rejects_empty_list(self):
        with pytest.raises(TargetValidationError):
            validate_targets([])

    def test_rejects_non_list(self):
        with pytest.raises(TargetValidationError):
            validate_targets("10.0.0.1")  # type: ignore[arg-type]

    def test_rejects_non_string_entries(self):
        with pytest.raises(TargetValidationError):
            validate_targets([10.0])  # type: ignore[list-item]

    def test_rejects_overlong_list(self):
        with pytest.raises(TargetValidationError):
            validate_targets([f"10.0.0.{i % 256}" for i in range(70)])
