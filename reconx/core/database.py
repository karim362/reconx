"""SQLite persistence for resume support - Production Grade."""
import json
import sqlite3
from datetime import datetime
from reconx.core.models import HostInfo


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                host TEXT PRIMARY KEY,
                ip TEXT, cname TEXT, status INT,
                server TEXT, title TEXT, tech TEXT,
                cdn TEXT, takeover TEXT, ports TEXT,
                robots TEXT, sitemap TEXT, endpoints TEXT,
                screenshot TEXT, nuclei TEXT, ts TEXT,
                secrets TEXT, cors TEXT, js_endpoints TEXT, s3_buckets TEXT,
                status_category TEXT, cname_chain TEXT, ip_intel TEXT,
                soft404 INT DEFAULT 0
            )
        """)
        # ترحيل الأعمدة الجديدة تلقائياً إذا كانت قاعدة البيانات قديمة
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(hosts)").fetchall()}
        new_cols = {
            "secrets": "TEXT", "cors": "TEXT", "js_endpoints": "TEXT",
            "s3_buckets": "TEXT", "status_category": "TEXT",
            "cname_chain": "TEXT", "ip_intel": "TEXT", "soft404": "INT"
        }
        for col, col_type in new_cols.items():
            if col not in cols:
                self.conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {col_type}")
        self.conn.commit()

    def save(self, info: HostInfo):
        """حفظ معلومات النقطة بشكل آمن متوافق مع الأعمدة الفعلية."""
        cursor = self.conn.cursor()
        cols = [r[1] for r in cursor.execute("PRAGMA table_info(hosts)").fetchall()]
        
        values = {
            "host": info.host,
            "ip": info.ip or "",
            "cname": info.cname or "",
            "status": info.status if info.status is not None else 0,
            "server": info.server or "N/A",
            "title": info.title or "",
            "tech": ",".join(info.tech) if info.tech else "",
            "cdn": info.cdn or "",
            "takeover": info.takeover or "",
            "ports": ",".join(map(str, info.ports)) if info.ports else "",
            "robots": ",".join(info.robots) if info.robots else "",
            "sitemap": ",".join(info.sitemap) if info.sitemap else "",
            "endpoints": ",".join(info.endpoints) if info.endpoints else "",
            "screenshot": info.screenshot or "",
            "nuclei": json.dumps(info.nuclei) if info.nuclei else "[]",
            "ts": datetime.utcnow().isoformat(),
            "secrets": json.dumps(getattr(info, "secrets", [])),
            "cors": json.dumps(getattr(info, "cors", {})),
            "js_endpoints": ",".join(getattr(info, "js_endpoints", [])),
            "s3_buckets": json.dumps(getattr(info, "s3_buckets", [])),
            "status_category": getattr(info, "status_category", "unknown"),
            "cname_chain": json.dumps(getattr(info, "cname_chain", [])),
            "ip_intel": json.dumps(getattr(info, "ip_intel", {})),
            "soft404": 1 if getattr(info, "soft404", False) else 0
        }

        placeholders = ",".join(["?"] * len(cols))
        col_names = ",".join(cols)
        vals = [values.get(c, "") for c in cols]
        
        cursor.execute(f"INSERT OR REPLACE INTO hosts ({col_names}) VALUES ({placeholders})", vals)
        self.conn.commit()

    def load_all(self) -> list:
        """استرجاع جميع النتائج المحفوظة بأمان تام من التلف الفهري."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM hosts")
        cols = [description[0] for description in cursor.description]
        rows = cursor.fetchall()
        
        result = []
        for row in rows:
            row_dict = dict(zip(cols, row))
            try:
                info = HostInfo(
                    host=row_dict.get("host", ""),
                    ip=row_dict.get("ip"),
                    cname=row_dict.get("cname"),
                    status=row_dict.get("status"),
                    server=row_dict.get("server", "N/A"),
                    title=row_dict.get("title", ""),
                    tech=row_dict.get("tech", "").split(",") if row_dict.get("tech") else [],
                    cdn=row_dict.get("cdn"),
                    takeover=row_dict.get("takeover"),
                    ports=[int(x) for x in row_dict.get("ports", "").split(",") if x],
                    robots=row_dict.get("robots", "").split(",") if row_dict.get("robots") else [],
                    sitemap=row_dict.get("sitemap", "").split(",") if row_dict.get("sitemap") else [],
                    endpoints=row_dict.get("endpoints", "").split(",") if row_dict.get("endpoints") else [],
                    screenshot=row_dict.get("screenshot"),
                    nuclei=json.loads(row_dict.get("nuclei", "[]")) if row_dict.get("nuclei") else [],
                    secrets=json.loads(row_dict.get("secrets", "[]")) if row_dict.get("secrets") else [],
                    cors=json.loads(row_dict.get("cors", "{}")) if row_dict.get("cors") else {},
                    js_endpoints=row_dict.get("js_endpoints", "").split(",") if row_dict.get("js_endpoints") else [],
                    s3_buckets=json.loads(row_dict.get("s3_buckets", "[]")) if row_dict.get("s3_buckets") else [],
                    status_category=row_dict.get("status_category", "unknown"),
                    cname_chain=json.loads(row_dict.get("cname_chain", "[]")) if row_dict.get("cname_chain") else [],
                    ip_intel=json.loads(row_dict.get("ip_intel", "{}")) if row_dict.get("ip_intel") else {},
                    soft404=bool(row_dict.get("soft404", 0))
                )
                result.append(info)
            except Exception:
                continue
        return result

    def close(self):
        self.conn.close()
