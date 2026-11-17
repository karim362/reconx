"""SQLite persistence for resume support."""
import json
import sqlite3
from datetime import datetime
from reconx.core.models import HostInfo


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                host TEXT PRIMARY KEY,
                ip TEXT, cname TEXT, status INT,
                server TEXT, title TEXT, tech TEXT,
                cdn TEXT, takeover TEXT, ports TEXT,
                robots TEXT, sitemap TEXT, endpoints TEXT,
                screenshot TEXT, nuclei TEXT, ts TEXT
            )
        """)
        self.conn.commit()

    def save(self, info: HostInfo):
        self.conn.execute(
            "INSERT OR REPLACE INTO hosts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                info.host, info.ip, info.cname, info.status,
                info.server, info.title, ",".join(info.tech),
                info.cdn, info.takeover, ",".join(map(str, info.ports)),
                ",".join(info.robots), ",".join(info.sitemap),
                ",".join(info.endpoints), info.screenshot,
                json.dumps(info.nuclei),
                datetime.utcnow().isoformat(),
            ),
        )
        self.conn.commit()

    def load_all(self):
        rows = self.conn.execute("SELECT * FROM hosts").fetchall()
        result = []
        for r in rows:
            try:
                nuclei = json.loads(r[14]) if r[14] else []
            except Exception:
                nuclei = []
            result.append(HostInfo(
                host=r[0], ip=r[1], cname=r[2], status=r[3],
                server=r[4], title=r[5],
                tech=r[6].split(",") if r[6] else [],
                cdn=r[7], takeover=r[8],
                ports=[int(x) for x in r[9].split(",") if x] if r[9] else [],
                robots=r[10].split(",") if r[10] else [],
                sitemap=r[11].split(",") if r[11] else [],
                endpoints=r[12].split(",") if r[12] else [],
                screenshot=r[13], nuclei=nuclei,
            ))
        return result

    def close(self):
        self.conn.close()
