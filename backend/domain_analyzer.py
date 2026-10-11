"""
FraudGuard: Domain Normalization and Basic Characteristics Analyzer
Domain & SSL Intelligence

Provides generic domain sanitization, structural decomposition, and raw structural
risk signals (excessive hyphens, punycode, unusual subdomains, numeric density).
Does NOT calculate any risk scores or apply domain whitelists/blacklists.
"""

import re
from typing import Optional, Dict, Any, Tuple
import tldextract


def normalize_domain(raw_input: str) -> str:
    """
    Normalizes a domain or URL input into a clean FQDN hostname.
    Removes protocols, user credentials, ports, paths, query strings, and fragments.
    
    Example:
        'https://www.example.com/product/123?ref=45' -> 'example.com'
        'shop.store.co.uk:8080/cart' -> 'shop.store.co.uk'
    """
    if not raw_input or not isinstance(raw_input, str):
        raise ValueError("Domain input must be a non-empty string.")

    cleaned = raw_input.strip().lower()

    # Remove protocol prefix if present
    cleaned = re.sub(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', '', cleaned)

    # Remove authentication credentials (e.g., user:pass@)
    if '@' in cleaned:
        cleaned = cleaned.split('@', 1)[-1]

    # Remove paths, queries, and fragments
    for delimiter in ['/', '?', '#']:
        if delimiter in cleaned:
            cleaned = cleaned.split(delimiter, 1)[0]

    # Remove port specification (e.g., :8000)
    if ':' in cleaned:
        cleaned = cleaned.split(':', 1)[0]

    cleaned = cleaned.strip('. ')

    # Validate basic RFC hostname format
    if not cleaned or len(cleaned) > 253:
        raise ValueError(f"Invalid domain length: '{cleaned}'")

    label_regex = re.compile(r'^(?!-)[a-z0-9-_]{1,63}(?<!-)$', re.IGNORECASE)
    labels = cleaned.split('.')
    if len(labels) < 2:
        raise ValueError(f"Domain must contain at least a label and TLD: '{cleaned}'")

    for label in labels:
        if not label_regex.match(label):
            raise ValueError(f"Invalid hostname label '{label}' in domain '{cleaned}'")

    return cleaned


def extract_domain_parts(domain: str) -> Tuple[str, str, int]:
    """
    Extracts registered domain, subdomain, and subdomain count using public suffix rules.
    
    Returns:
        (registered_domain, subdomain, subdomain_count)
    """
    extracted = tldextract.extract(domain)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    return registered_domain, subdomain, subdomain_count


def analyze_domain_characteristics(domain: str, domain_age_days: Optional[int] = None) -> Dict[str, Any]:
    """
    Evaluates raw technical domain characteristics without computing any risk scores.
    """
    registered_domain, subdomain, subdomain_count = extract_domain_parts(domain)

    # Punycode / Internationalized Domain Name check
    is_punycode = domain.startswith("xn--") or ".xn--" in domain

    # Hyphen frequency check
    hyphen_count = domain.count("-")
    excessive_hyphens = hyphen_count >= 3

    # Long hostname check (> 30 characters)
    long_hostname = len(domain) > 30

    # Numeric density check (> 30% digits)
    digit_count = sum(1 for c in domain if c.isdigit())
    numeric_heavy = (digit_count / max(len(domain), 1)) > 0.3

    # Young domain threshold (conventionally < 90 days)
    is_young = (domain_age_days < 90) if domain_age_days is not None else None

    return {
        "is_young_domain": is_young,
        "domain_age_days": domain_age_days,
        "long_hostname": long_hostname,
        "excessive_hyphens": excessive_hyphens,
        "punycode": is_punycode,
        "numeric_heavy": numeric_heavy,
        "subdomain_count": subdomain_count,
        "registered_domain": registered_domain
    }
