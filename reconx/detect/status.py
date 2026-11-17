"""Status categorization."""
CATS = {200:"ok",201:"ok",204:"ok",301:"redirect",302:"redirect",307:"redirect",308:"redirect",
    400:"bad",401:"protected",403:"protected",405:"bad",429:"ratelimit",
    404:"notfound",410:"notfound",500:"error",502:"error",503:"error",504:"error"}
INTERESTING = {"protected","error","redirect"}

def categorize(s):
    return CATS.get(s, "other") if s else "unknown"

def is_interesting(s):
    return categorize(s) in INTERESTING

def emoji(s):
    return {"ok":"+","redirect":"~","protected":"!","error":"X","notfound":".","ratelimit":"~"}.get(categorize(s), "?")
