import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock

class AuditStore:
    def __init__(self,path="sentinelops-audit.sqlite3"):
        self.path=path; self.lock=Lock()
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,actor TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL)")
    def _connect(self):
        db=sqlite3.connect(self.path,timeout=5); db.row_factory=sqlite3.Row; return db
    def record(self,event,actor,details):
        with self.lock,self._connect() as db:
            cur=db.execute("INSERT INTO audit(event,actor,details,created_at) VALUES(?,?,?,?)",
                (event,actor,json.dumps(details,sort_keys=True),datetime.now(timezone.utc).isoformat()))
            row=db.execute("SELECT * FROM audit WHERE id=?",(cur.lastrowid,)).fetchone()
        return {"id":row["id"],"event":row["event"],"actor":row["actor"],
            "details":json.loads(row["details"]),"created_at":row["created_at"]}
    def list(self,limit=100):
        with self.lock,self._connect() as db:
            rows=db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
        return [{"id":r["id"],"event":r["event"],"actor":r["actor"],
            "details":json.loads(r["details"]),"created_at":r["created_at"]} for r in rows]
