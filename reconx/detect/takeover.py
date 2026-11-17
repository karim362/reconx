TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "Bad request",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "readme.io": "Project doesnt exist... yet!",
}


def detect(host, cname, body):
    if not cname or not body:
        return None
    cl = cname.lower()
    body_l = body.lower()
    for svc, fp in TAKEOVER_FINGERPRINTS.items():
        if svc in cl and fp.lower() in body_l:
            return svc
    return None
