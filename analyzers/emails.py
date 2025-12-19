# analyzers/emails.py
"""
Emails analyzer.

Detects URLs containing email addresses in paths, query parameters,
or other URL components.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional, List, Set

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


# Email regex - reasonably strict
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

# Common email providers (for whitelisting)
COMMON_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "live.com", "msn.com", "gmx.com", "mail.com",
    "icloud.com", "protonmail.com", "yandex.com",
})


def _extract_emails(text: str) -> Set[str]:
    """Extract all email addresses from text."""
    if not text:
        return set()
    return set(EMAIL_REGEX.findall(text))


def _is_valid_tld(domain: str) -> bool:
    """Basic TLD validation."""
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return False
    
    tld = parts[-1]
    # Reject obvious non-TLDs
    if len(tld) < 2 or len(tld) > 10:
        return False
    if tld.isdigit():
        return False
    
    return True


@register
class EmailsAnalyzer(BaseAnalyzer):
    """
    Detect URLs containing email addresses.
    
    Extracts emails from:
    - Query parameters
    - Path segments
    - Full URL
    
    Validates email format and TLD.
    """
    
    @property
    def name(self) -> str:
        return "emails"
    
    @property
    def description(self) -> str:
        return "Detect URLs containing email addresses"
    
    @property
    def output_filename(self) -> str:
        return "emails.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Skip static assets - emails unlikely in image/css URLs."""
        return True
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL contains valid email addresses."""
        # Check query params
        for values in parsed.params.values():
            for value in values:
                emails = _extract_emails(value)
                for email in emails:
                    domain = email.split("@")[1]
                    if _is_valid_tld(domain):
                        return True
        
        # Check path
        emails = _extract_emails(parsed.path)
        for email in emails:
            domain = email.split("@")[1]
            if _is_valid_tld(domain):
                return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract found emails."""
        all_emails: Set[str] = set()
        
        # From params
        for values in parsed.params.values():
            for value in values:
                all_emails.update(_extract_emails(value))
        
        # From path
        all_emails.update(_extract_emails(parsed.path))
        
        # Filter valid and mask
        valid_emails: List[str] = []
        domains: Set[str] = set()
        
        for email in all_emails:
            domain = email.split("@")[1].lower()
            if _is_valid_tld(domain):
                # Mask email for privacy
                local, dom = email.split("@")
                if len(local) > 2:
                    masked = f"{local[0]}{'*' * (len(local)-2)}{local[-1]}@{dom}"
                else:
                    masked = f"{'*' * len(local)}@{dom}"
                valid_emails.append(masked)
                domains.add(domain)
        
        if valid_emails:
            return {
                "email_count": len(valid_emails),
                "domains": list(domains),
                "has_common_provider": bool(domains & COMMON_PROVIDERS),
            }
        
        return None
