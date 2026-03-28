"""IOC data models."""

from dataclasses import dataclass
from enum import Enum


class IOCType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    EMAIL = "email"
    CVE = "cve"


HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512})
IP_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6})


@dataclass(frozen=True)
class IOC:
    value: str
    type: IOCType
    raw: str = ""

    def __hash__(self) -> int:
        return hash((self.value, self.type))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IOC) and self.value == other.value and self.type == other.type
