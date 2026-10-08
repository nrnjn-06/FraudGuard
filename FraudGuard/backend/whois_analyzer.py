"""
FraudGuard: WHOIS and Domain Age Analyzer
Domain WHOIS Intelligence

Collects raw domain registration information, calculates exact domain age in days/years,
and returns structured technical signals. Handles network timeouts and missing records safely.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
import whois


def _extract_earliest_date(date_val: Union[datetime, List[datetime], None]) -> Optional[datetime]:
    """
    Normalizes a date or list of dates returned by WHOIS, picking the earliest valid datetime.
    """
    if date_val is None:
        return None

    if isinstance(date_val, list):
        valid_dates = [d for d in date_val if isinstance(d, datetime)]
        if not valid_dates:
            return None
        return min(valid_dates)

    if isinstance(date_val, datetime):
        return date_val

    return None


def _format_iso(dt: Optional[datetime]) -> Optional[str]:
    """Converts datetime to ISO 8601 string in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def analyze_whois(registered_domain: str) -> Dict[str, Any]:
    """
    Queries WHOIS data for the registered domain and computes domain age.
    Never raises unhandled exceptions.
    """
    try:
        query_result = whois.whois(registered_domain)
        if not query_result or not getattr(query_result, 'domain_name', None):
            return {
                "available": False,
                "domain": registered_domain,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "domain_age_days": None,
                "domain_age_years": None,
                "name_servers": [],
                "status": None,
                "error": "WHOIS record not found or unavailable"
            }

        # Parse creation date and compute age
        creation_dt = _extract_earliest_date(query_result.creation_date)
        expiration_dt = _extract_earliest_date(query_result.expiration_date)
        updated_dt = _extract_earliest_date(query_result.updated_date)

        domain_age_days = None
        domain_age_years = None

        if creation_dt:
            # Normalize to UTC for accurate subtraction
            dt_now = datetime.now(timezone.utc)
            if creation_dt.tzinfo is None:
                aware_creation = creation_dt.replace(tzinfo=timezone.utc)
            else:
                aware_creation = creation_dt.astimezone(timezone.utc)

            delta = dt_now - aware_creation
            domain_age_days = max(0, delta.days)
            domain_age_years = round(domain_age_days / 365.25, 2)

        # Parse name servers into a clean list of lower-case strings
        raw_ns = getattr(query_result, 'name_servers', [])
        name_servers: List[str] = []
        if isinstance(raw_ns, list):
            name_servers = [str(ns).lower() for ns in raw_ns if ns]
        elif isinstance(raw_ns, str) and raw_ns.strip():
            name_servers = [raw_ns.strip().lower()]

        # Parse registrar
        raw_registrar = getattr(query_result, 'registrar', None)
        registrar = str(raw_registrar).strip() if raw_registrar else None

        # Parse status
        raw_status = getattr(query_result, 'status', None)
        status = None
        if isinstance(raw_status, list):
            status = [str(s) for s in raw_status if s]
        elif raw_status:
            status = str(raw_status)

        return {
            "available": True,
            "domain": registered_domain,
            "registrar": registrar,
            "creation_date": _format_iso(creation_dt),
            "expiration_date": _format_iso(expiration_dt),
            "updated_date": _format_iso(updated_dt),
            "domain_age_days": domain_age_days,
            "domain_age_years": domain_age_years,
            "name_servers": name_servers,
            "status": status,
            "error": None
        }

    except Exception as e:
        return {
            "available": False,
            "domain": registered_domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "domain_age_days": None,
            "domain_age_years": None,
            "name_servers": [],
            "status": None,
            "error": f"WHOIS query failed: {type(e).__name__}: {str(e)}"
        }
