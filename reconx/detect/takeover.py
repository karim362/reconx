"""Subdomain Takeover Detection Module."""

SIGNATURES = {
    "GitHub": ["there isn't a github pages site here", "fastly error: unknown domain"],
    "AWS S3": ["nosuchbucket", "the specified bucket does not exist"],
    "Heroku": ["no such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Azure": ["404 web site not found", "error 404 - website not found"],
    "Vercel": ["the deployment could not be found", "domain not found"],
    "Netlify": ["not found - 404"],
}

def detect(host, cname, body):
    """Check if the host or its CNAME indicates a potential subdomain takeover."""
    if not body:
        return False
    body_lower = body.lower()
    for service, sigs in SIGNATURES.items():
        for sig in sigs:
            if sig in body_lower:
                return True
    return False
