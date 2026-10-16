"""SQLite boundary: parameterized values, transactions and bounded-lived records."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(Path(__file__).with_name("schema.sql").read_text())

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def consume(self, keys, now, window=600):
        """Atomic fixed-window admission. All keys checked before incrementing."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM rate_limits WHERE resets_at <= ?", (now,))
            blocked = []
            for key, limit in keys:
                row = db.execute(
                    "SELECT * FROM rate_limits WHERE key = ?", (key,)
                ).fetchone()
                if row and row["attempts"] >= limit:
                    blocked.append(row["resets_at"] - now)
            if blocked:
                return max(blocked)
            for key, _ in keys:
                db.execute(
                    "INSERT INTO rate_limits VALUES (?, 1, ?) "
                    "ON CONFLICT(key) DO UPDATE SET attempts = attempts + 1",
                    (key, now + window),
                )
        return 0
