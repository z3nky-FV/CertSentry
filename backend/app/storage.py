"""Tiny persistent inventory backed by Python's built-in SQLite driver."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .config import DATABASE_PATH


class CertificateStore:
    def __init__(self, path: Path = DATABASE_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, timeout=5)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                id INTEGER NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY (hostname, port)
            )
        """)
        self._db.commit()

    def load_all(self) -> list[dict]:
        rows = self._db.execute("SELECT payload FROM certificates").fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_many(self, certificates: Iterable[dict]) -> None:
        rows = [
            (c["hostname"].lower(), c["port"], c["id"],
             json.dumps(c, ensure_ascii=False, separators=(",", ":")))
            for c in certificates
        ]
        if not rows:
            return
        with self._db:
            self._db.executemany("""
                INSERT INTO certificates(hostname, port, id, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hostname, port) DO UPDATE SET
                    id = excluded.id, payload = excluded.payload
            """, rows)
