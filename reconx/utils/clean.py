import re


def clean_subdomain(name, domain):
    """Normalize and validate a subdomain. Return None if invalid."""
    name = name.strip().lower().rstrip(".").lstrip("*.")
    if not name or not name.endswith(domain):
        return None
    if not re.fullmatch(r"[a-z0-9]([a-z0-9\-\.]{0,250})?[a-z0-9]", name):
        return None
    return name
