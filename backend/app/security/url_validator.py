"""
PHANTOM URL Validation & SSRF Protection
Validates user-submitted URLs and blocks access to private/reserved networks.
"""
import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse
from typing import Optional

import validators

logger = logging.getLogger("phantom.security.url_validator")

# Private / reserved IP ranges that must be blocked
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("10.0.0.0/8"),        # Private (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("172.16.0.0/12"),     # Private (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),    # 6to4 relay
    ipaddress.ip_network("192.168.0.0/16"),    # Private (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique local
    ipaddress.ip_network("fe80::/10"),         # Link-local
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",  # Cloud metadata
    "169.254.169.254",           # AWS/GCP metadata endpoint
}

# Allowed URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Maximum URL length
MAX_URL_LENGTH = 2048


class URLValidationError(Exception):
    """Raised when URL validation fails."""
    pass


def validate_url(url: str) -> str:
    """
    Validate and sanitize a user-submitted URL.
    Returns the cleaned URL or raises URLValidationError.
    """
    if not url or not isinstance(url, str):
        raise URLValidationError("URL must be a non-empty string")

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError("Failed to parse URL")

    # Validate scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Scheme '{parsed.scheme}' is not allowed. Use http or https.")

    # Extract hostname
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL must contain a valid hostname")

    # Block known dangerous hostnames
    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES:
        raise URLValidationError(f"Hostname '{hostname}' is blocked for security reasons")

    # Validate the hostname format
    if not _is_valid_hostname(hostname):
        raise URLValidationError(f"Invalid hostname: {hostname}")

    # Check for IP-based URLs and validate the IP
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_blocked_ip(ip):
            raise URLValidationError(f"Access to IP address {hostname} is blocked (private/reserved range)")
    except ValueError:
        # Not an IP — it's a domain name, resolve and check
        pass

    # Block port-based attacks on common internal services
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        logger.warning("Non-standard port %d in URL: %s", parsed.port, url)

    return url


def validate_resolved_ip(hostname: str) -> Optional[str]:
    """
    Resolve hostname and validate the resulting IP is not private/reserved.
    Returns the resolved IP or raises URLValidationError.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if _is_blocked_ip(ip):
                raise URLValidationError(
                    f"Hostname '{hostname}' resolves to blocked IP {ip_str} (private/reserved range)"
                )
            return ip_str
    except socket.gaierror:
        raise URLValidationError(f"Failed to resolve hostname: {hostname}")
    except URLValidationError:
        raise
    except Exception as e:
        raise URLValidationError(f"Error resolving hostname '{hostname}': {e}")

    return None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address falls within a blocked range."""
    for network in BLOCKED_NETWORKS:
        try:
            if ip in network:
                return True
        except TypeError:
            # IPv4/IPv6 mismatch — skip
            continue
    return False


def _is_valid_hostname(hostname: str) -> bool:
    """Validate hostname format."""
    if len(hostname) > 253:
        return False
    # Allow IP addresses
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    # Domain validation
    return validators.domain(hostname) is True


def extract_hostname(url: str) -> str:
    """Extract the hostname from a URL."""
    parsed = urlparse(url)
    return parsed.hostname or ""
