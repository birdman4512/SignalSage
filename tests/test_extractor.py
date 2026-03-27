"""Tests for the IOC extractor."""

import pytest
from signalsage.ioc.extractor import extract
from signalsage.ioc.models import IOCType


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

def test_ipv4_standard():
    iocs = extract("Malicious IP observed: 8.8.4.4")
    assert any(i.value == "8.8.4.4" and i.type == IOCType.IPV4 for i in iocs)


def test_ipv4_defanged_brackets():
    iocs = extract("Attacker: 185.220.101[.]45")
    assert any(i.value == "185.220.101.45" and i.type == IOCType.IPV4 for i in iocs)


def test_ipv4_defanged_full():
    iocs = extract("C2: 1[.]2[.]3[.]4")
    assert any(i.value == "1.2.3.4" and i.type == IOCType.IPV4 for i in iocs)


def test_private_ip_filtered():
    for private in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"):
        iocs = extract(f"internal host: {private}")
        assert not any(i.type == IOCType.IPV4 for i in iocs), f"{private} should be filtered"


def test_multiple_ips():
    iocs = extract("hosts: 8.8.8.8 and 1.1.1.1 contacted 185.220.101.45")
    ip_values = {i.value for i in iocs if i.type == IOCType.IPV4}
    assert {"8.8.8.8", "1.1.1.1", "185.220.101.45"} == ip_values


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

def test_md5():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract(f"MD5: {md5}")
    assert any(i.value == md5 and i.type == IOCType.MD5 for i in iocs)


def test_sha1():
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    iocs = extract(f"SHA1: {sha1}")
    assert any(i.value == sha1 and i.type == IOCType.SHA1 for i in iocs)


def test_sha256():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract(f"SHA256: {sha256}")
    assert any(i.value == sha256 and i.type == IOCType.SHA256 for i in iocs)


def test_sha512():
    sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" + "0" * 1
    # generate a proper 128-char hex
    sha512 = "a" * 128
    iocs = extract(f"Hash: {sha512}")
    assert any(i.value == sha512 and i.type == IOCType.SHA512 for i in iocs)


def test_sha256_not_classified_as_md5():
    """A SHA256 (64 chars) must not also appear as MD5 (32 chars)."""
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract(f"Hash: {sha256}")
    types_for_hash = {i.type for i in iocs if sha256.startswith(i.value)}
    assert IOCType.MD5 not in types_for_hash
    assert IOCType.SHA1 not in types_for_hash


def test_hash_case_normalised():
    md5 = "D41D8CD98F00B204E9800998ECF8427E"
    iocs = extract(f"hash {md5}")
    assert any(i.value == md5.lower() and i.type == IOCType.MD5 for i in iocs)


# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------

def test_cve_standard():
    iocs = extract("Patch CVE-2023-12345 immediately")
    assert any(i.value == "CVE-2023-12345" and i.type == IOCType.CVE for i in iocs)


def test_cve_case_insensitive():
    iocs = extract("cve-2021-44228 log4shell")
    assert any(i.value == "CVE-2021-44228" and i.type == IOCType.CVE for i in iocs)


def test_cve_long_id():
    iocs = extract("CVE-2023-1234567 affects OpenSSL")
    assert any(i.value == "CVE-2023-1234567" for i in iocs)


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

def test_url_standard():
    iocs = extract("Payload at https://evil.example.org/malware.exe")
    assert any(i.type == IOCType.URL for i in iocs)


def test_url_defanged_hxxp():
    iocs = extract("Dropper: hxxps://bad[.]actor/payload")
    url_iocs = [i for i in iocs if i.type == IOCType.URL]
    assert url_iocs
    assert "https://" in url_iocs[0].value


# ---------------------------------------------------------------------------
# Code block stripping
# ---------------------------------------------------------------------------

def test_code_block_stripped():
    iocs = extract("```\n8.8.8.8\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n```")
    assert not any(i.type == IOCType.IPV4 for i in iocs)
    assert not any(i.type == IOCType.SHA256 for i in iocs)


def test_inline_code_stripped():
    iocs = extract("run `8.8.8.8` in your terminal")
    assert not any(i.type == IOCType.IPV4 for i in iocs)


# ---------------------------------------------------------------------------
# Benign domain filtering
# ---------------------------------------------------------------------------

def test_benign_domain_filtered():
    iocs = extract("See https://google.com/search?q=malware")
    domain_iocs = [i for i in iocs if i.type == IOCType.DOMAIN and i.value == "google.com"]
    assert not domain_iocs


def test_non_benign_domain_kept():
    iocs = extract("C2 at evil-malware-c2.ru")
    assert any(i.type == IOCType.DOMAIN for i in iocs)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def test_email():
    iocs = extract("Contact attacker@evil.ru for ransom")
    assert any(i.value == "attacker@evil.ru" and i.type == IOCType.EMAIL for i in iocs)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_no_duplicates():
    iocs = extract("IP 8.8.8.8 contacted 8.8.8.8 again")
    ip_iocs = [i for i in iocs if i.value == "8.8.8.8"]
    assert len(ip_iocs) == 1
