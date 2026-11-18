"""Data models."""
from dataclasses import dataclass, field, asdict
from typing import Optional

@dataclass
class HostInfo:
    host: str
    ip: Optional[str] = None
    cname: Optional[str] = None
    status: Optional[int] = None
    server: str = "N/A"
    title: str = ""
    tech: list = field(default_factory=list)
    cdn: Optional[str] = None
    takeover: Optional[str] = None
    ports: list = field(default_factory=list)
    robots: list = field(default_factory=list)
    sitemap: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    screenshot: Optional[str] = None
    nuclei: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    cors: dict = field(default_factory=dict)
    js_endpoints: list = field(default_factory=list)
    s3_buckets: list = field(default_factory=list)
    status_category: str = "unknown"
    cname_chain: list = field(default_factory=list)
    ip_intel: dict = field(default_factory=dict)
    soft404: bool = False

    def to_dict(self):
        return asdict(self)
