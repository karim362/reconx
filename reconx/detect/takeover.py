"""Subdomain takeover v2 - 40+ services."""
SERVICES = {
    "github.io":"There isn't a GitHub Pages site here",
    "herokuapp.com":"No such app","s3.amazonaws.com":"NoSuchBucket",
    "cloudfront.net":"Bad request","azurewebsites.net":"404 Web Site not found",
    "cloudapp.net":"404 Web Site not found","blob.core.windows.net":"BlobNotFound",
    "azurestaticapps.net":"404","shopify.com":"Sorry, this shop is currently unavailable",
    "myshopify.com":"Sorry, this shop is currently unavailable",
    "tumblr.com":"Whatever you were looking for doesn't currently exist",
    "wordpress.com":"Do you want to register","ghost.io":"Domain error",
    "surge.sh":"project not found","bitbucket.io":"Repository not found",
    "zendesk.com":"Help Center Closed","readme.io":"Project doesnt exist",
    "readthedocs.io":"unknown to Read the Docs","fly.io":"404 Not Found",
    "netlify.app":"Not Found - Request ID","netlify.com":"Not Found - Request ID",
    "vercel.app":"The deployment could not be found","vercel.com":"The deployment could not be found",
    "webflow.io":"This site is not published","statuspage.io":"You are being redirected",
    "desk.com":"Sorry, this page is missing","fastly.net":"Fastly error: unknown domain",
    "ngrok.io":"Tunnel not found","ngrok-free.app":"Tunnel not found",
    "launchrock.com":"Site not found","cargo.site":"404 Not Found",
    "smugmug.com":"Page Not Found","tictail.com":"Sorry, this shop is currently unavailable",
    "smartjobboard.com":"Not Found","teamwork.com":"Oops - We didn't find your site",
    "helpscoutdocs.com":"No settings were found","feedpress.me":"The feed has not been found",
    "pantheon.io":"The gods are wise","unbounce.com":"The requested URL was not found",
    "myshopify.com":"Sorry, this shop is currently unavailable","ghost.io":"Domain error",
}

def detect(host, cname, body):
    if not cname or not body: return None
    cl, bl = cname.lower(), body.lower()
    for svc, fp in SERVICES.items():
        if svc in cl and fp.lower() in bl: return svc
    return None
