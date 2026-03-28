"""Shodan threat intelligence provider."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://api.shodan.io"

# Common port → service name mapping
_PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE/VPN",
    514: "Syslog",
    515: "LPD/Print",
    587: "SMTP (submission)",
    631: "IPP/CUPS",
    636: "LDAPS",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    1883: "MQTT",
    2049: "NFS",
    2375: "Docker (unencrypted)",
    2376: "Docker TLS",
    2483: "Oracle DB",
    3000: "Node.js/Grafana",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit",
    5000: "UPnP/Flask",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP/RabbitMQ",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    7001: "WebLogic",
    8000: "HTTP alt",
    8080: "HTTP proxy",
    8443: "HTTPS alt",
    8888: "Jupyter",
    9000: "SonarQube/PHP-FPM",
    9042: "Cassandra",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch cluster",
    11211: "Memcached",
    15672: "RabbitMQ mgmt",
    27017: "MongoDB",
    27018: "MongoDB",
    50000: "SAP",
    50070: "Hadoop NameNode",
}


class ShodanProvider(BaseProvider):
    name = "Shodan"
    supported_types = [IOCType.IPV4]
    requires_key = True

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        if not self.api_key:
            return self._error(ioc, "No API key configured")

        url = f"{_BASE}/shodan/host/{ioc.value}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params={"key": self.api_key})
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=False,
                        summary="No information found",
                    )
                if resp.status_code == 401:
                    return self._error(ioc, "Invalid API key")
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("Shodan lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        ports = data.get("ports", [])
        org = data.get("org", "Unknown")
        country = data.get("country_name", "Unknown")
        tags = data.get("tags", [])
        vulns: dict = data.get("vulns", {})

        port_labels = [
            f"{p}/{_PORT_SERVICES[p]}" if p in _PORT_SERVICES else str(p)
            for p in sorted(ports)[:10]
        ]
        ports_str = ", ".join(port_labels)
        summary = f"Org: {org} | Country: {country}\nPorts: {ports_str}"
        if tags:
            summary += f"\nTags: {', '.join(tags[:5])}"
        if vulns:
            cve_list = ", ".join(list(vulns.keys())[:5])
            summary += f"\nCVEs: {cve_list}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=bool(vulns),
            score=min(len(vulns) * 10, 100) if vulns else 0,
            summary=summary,
            details={
                "ports": ports,
                "org": org,
                "country": country,
                "tags": tags,
                "vulns": list(vulns.keys()),
                "hostnames": data.get("hostnames", []),
            },
            report_url=f"https://www.shodan.io/host/{ioc.value}",
        )
