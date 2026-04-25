"""Tests for integrations.nmap._parse_xml.

The parser turns `nmap -oX -` output into our Device/Service shape.
We don't shell out to nmap in tests — we feed hand-built XML fixtures
and verify the parser extracts what we promise.

Covers:
  - Host + port + service extraction.
  - Down hosts skipped.
  - MAC address coexists with IP (-oX emits both).
  - Closed ports ignored (only open / open|filtered pass through).
  - OS fingerprint guess surfaces when present.
  - Empty / malformed XML doesn't crash.
"""

from __future__ import annotations

from integrations.nmap import _parse_xml


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
