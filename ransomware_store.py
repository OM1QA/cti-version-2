# ransomware_store.py
# Lightweight SQLite helpers for the "Ransomware Groups" feature.

import json
import sqlite3
from contextlib import contextmanager
from typing import Dict, Any, Optional

DB_PATH = "ransomware.db"
_mem_snapshot: Optional[Dict[str, Any]] = None

@contextmanager
def _conn():
    try:
        c = sqlite3.connect(DB_PATH, timeout=5)
        yield c
        c.commit()
        c.close()
    except Exception:
        yield None

def init_db() -> bool:
    try:
        with _conn() as c:
            if c is None:
                return False
            c.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_groups (
              id TEXT PRIMARY KEY,
              aliases TEXT,
              last_seen TEXT,
              summary TEXT,
              top_stories TEXT,
              recent_victims TEXT
            );""")
            c.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_stories (
              id TEXT PRIMARY KEY,
              group_id TEXT,
              title TEXT,
              link TEXT,
              published TEXT,
              FOREIGN KEY(group_id) REFERENCES ransomware_groups(id)
            );""")
            c.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_victims (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_id TEXT,
              name TEXT,
              date TEXT,
              source TEXT,
              FOREIGN KEY(group_id) REFERENCES ransomware_groups(id)
            );""")
        return True
    except Exception:
        return False

def clear_and_save(payload: Dict[str, Any]) -> bool:
    ok = init_db()
    if ok:
        try:
            with _conn() as c:
                if c is None:
                    raise RuntimeError("No DB connection")
                c.execute("DELETE FROM ransomware_groups;")
                c.execute("DELETE FROM ransomware_stories;")
                c.execute("DELETE FROM ransomware_victims;")
                groups = (payload or {}).get("groups", {})
                for gid, entry in groups.items():
                    c.execute(
                        "REPLACE INTO ransomware_groups (id, aliases, last_seen, summary, top_stories, recent_victims) VALUES (?,?,?,?,?,?)",
                        (
                            gid,
                            json.dumps(entry.get("aliases", [])),
                            entry.get("last_seen", ""),
                            entry.get("summary", ""),
                            json.dumps(entry.get("top_stories", [])),
                            json.dumps(entry.get("victims", [])),
                        ),
                    )
            return True
        except Exception:
            pass
    global _mem_snapshot
    _mem_snapshot = payload or {"groups": {}, "last_updated": None}
    return False

def load_groups() -> Dict[str, Any]:
    try:
        with _conn() as c:
            if c is not None:
                rows = c.execute("SELECT id, aliases, last_seen, summary, top_stories, recent_victims FROM ransomware_groups").fetchall()
                if rows:
                    groups = {}
                    for (gid, aliases, last_seen, summary, top_stories, recent_victims) in rows:
                        groups[gid] = {
                            "aliases": json.loads(aliases or "[]"),
                            "last_seen": last_seen,
                            "summary": summary or "",
                            "top_stories": json.loads(top_stories or "[]"),
                            "victims": json.loads(recent_victims or "[]"),
                        }
                    return {"groups": groups}
    except Exception:
        pass
    return _mem_snapshot or {"groups": {}}
