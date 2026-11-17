import re

TECH_PATTERNS = {
    "WordPress":  [r"wp-content", r"wp-includes"],
    "Joomla":     [r"/components/com_"],
    "Drupal":     [r"Drupal\.settings"],
    "Laravel":    [r"laravel_session"],
    "Django":     [r"csrfmiddlewaretoken"],
    "React":      [r"__REACT_DEVTOOLS", r"_reactRootContainer"],
    "Vue":        [r"__VUE__", r"vue-router"],
    "Angular":    [r"ng-version", r"ng-app"],
    "jQuery":     [r"jquery(?:\.min)?\.js"],
    "Bootstrap":  [r"bootstrap(?:\.min)?\.(?:css|js)"],
    "PHP":        [r"PHPSESSID"],
    "Next.js":    [r"__NEXT_DATA__"],
    "Nuxt":       [r"__NUXT__"],
    "Svelte":     [r"svelte-"],
    "Tailwind":   [r"tailwind"],
    "GraphQL":    [r"graphql"],
    "Swagger":    [r"swagger-ui"],
}


def detect(headers, body):
    srv = headers.get("Server", "")
    blob = (body[:4000] if body else "") + " " + srv + " " + \
           " ".join(f"{k}:{v}" for k, v in headers.items())
    found = []
    for tech, pats in TECH_PATTERNS.items():
        for p in pats:
            if re.search(p, blob, re.I):
                found.append(tech)
                break
    return list(dict.fromkeys(found))
