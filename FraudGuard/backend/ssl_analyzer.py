"""
FraudGuard: SSL/TLS Certificate Analyzer
SSL/TLS Intelligence

Inspects SSL/TLS certificates on port 443. Extracts validity periods, issuer, subject,
and TLS version. Handles self-signed, expired, hostname mismatches, and connection failures safely.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def _parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parses standard OpenSSL certificate date strings e.g. 'May 15 12:00:00 2026 GMT'."""
    if not date_str:
        return None
    try:
        # Standard OpenSSL format: '%b %d %H:%M:%S %Y %Z'
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            # Fallback without timezone
            parts = date_str.rsplit(' ', 1)[0]
            dt = datetime.strptime(parts, "%b %d %H:%M:%S %Y")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _format_dict_or_str(data: Any) -> Optional[str]:
    """Helper to convert subject/issuer tuples or dicts into a readable string."""
    if not data:
        return None
    if isinstance(data, dict):
        cn = data.get('commonName')
        org = data.get('organizationName')
        if cn and org:
            return f"{org} ({cn})"
        return cn or org or str(data)
    if isinstance(data, (list, tuple)):
        extracted = {}
        for item in data:
            if isinstance(item, (list, tuple)):
                for subitem in item:
                    if isinstance(subitem, (list, tuple)) and len(subitem) == 2:
                        extracted[subitem[0]] = subitem[1]
        return _format_dict_or_str(extracted)
    return str(data)


def analyze_ssl(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Connects to hostname:443 and inspects the TLS certificate.
    Returns structured technical signals without crashing on failure.
    """
    # Default structure on failure
    result: Dict[str, Any] = {
        "available": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "tls_version": None,
        "hostname_verified": False,
        "error": None
    }

    # Attempt 1: Standard verified connection
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                not_before = _parse_cert_date(cert.get('notBefore'))
                not_after = _parse_cert_date(cert.get('notAfter'))
                now = datetime.now(timezone.utc)

                days_until_expiry = None
                is_currently_valid = True

                if not_after:
                    days_until_expiry = (not_after - now).days
                    if not_after < now:
                        is_currently_valid = False

                if not_before and not_before > now:
                    is_currently_valid = False

                issuer_str = _format_dict_or_str(cert.get('issuer'))
                subject_str = _format_dict_or_str(cert.get('subject'))

                return {
                    "available": True,
                    "valid": is_currently_valid,
                    "issuer": issuer_str,
                    "subject": subject_str,
                    "valid_from": not_before.isoformat() if not_before else None,
                    "valid_until": not_after.isoformat() if not_after else None,
                    "days_until_expiry": days_until_expiry,
                    "tls_version": tls_version,
                    "hostname_verified": True,
                    "error": None
                }

    except ssl.SSLCertVerificationError as cert_err:
        # Verification failed (e.g. expired, self-signed, untrusted, or name mismatch)
        result["available"] = True
        result["valid"] = False
        result["hostname_verified"] = False
        result["error"] = f"Certificate verification failed: {cert_err.verify_message}"

        # Attempt fallback unverified connection to inspect the certificate dates & issuer
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    result["tls_version"] = ssock.version()
                    if cert:
                        not_before = _parse_cert_date(cert.get('notBefore'))
                        not_after = _parse_cert_date(cert.get('notAfter'))
                        now = datetime.now(timezone.utc)
                        if not_after:
                            result["days_until_expiry"] = (not_after - now).days
                            result["valid_until"] = not_after.isoformat()
                        if not_before:
                            result["valid_from"] = not_before.isoformat()
                        result["issuer"] = _format_dict_or_str(cert.get('issuer'))
                        result["subject"] = _format_dict_or_str(cert.get('subject'))
        except Exception:
            pass

        return result

    except socket.timeout:
        result["error"] = "Connection timed out connecting to port 443"
        return result

    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 443 (HTTPS not supported or blocked)"
        return result

    except socket.gaierror:
        result["error"] = "DNS resolution failed for hostname"
        return result

    except ssl.SSLError as ssl_err:
        result["error"] = f"SSL Handshake failed: {str(ssl_err)}"
        return result

    except Exception as general_err:
        result["error"] = f"Unable to establish TLS connection: {type(general_err).__name__}: {str(general_err)}"
        return result
