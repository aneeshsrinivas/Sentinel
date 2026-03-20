"""
SENTINEL Telemetry Store - SQLite persistence with WAL mode.
"""
import sqlite3
import time
from typing import List, Tuple, Any, Dict


class TelemetryStore:
    """SQLite-backed telemetry with WAL mode and batched writes."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._pending_writes = []
        self._last_flush = time.time()
        self._flush_interval = 5.0

    def _init_db(self):
        c = self.conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                feature_id TEXT,
                confidence REAL,
                event_type TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                score REAL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS mitigation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                tier INTEGER,
                score REAL,
                description TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                feature_id TEXT,
                mean REAL,
                variance REAL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scores_ts ON scores(ts)")
        self.conn.commit()

    def log_anomaly_event(self, event: Any):
        """Log an anomaly event. Accepts object with feature_id, confidence, timestamp."""
        fid = getattr(event, 'feature_id', 'unknown')
        conf = getattr(event, 'confidence', 0.0)
        ts = getattr(event, 'timestamp', time.time())
        self._pending_writes.append(
            ("INSERT INTO events (ts, feature_id, confidence, event_type) VALUES (?,?,?,?)",
             (ts, fid, conf, 'anomaly'))
        )
        self._maybe_flush()

    def log_mitigation_action(self, action: Any):
        """Log a mitigation action."""
        ts = getattr(action, 'timestamp', time.time())
        tier = getattr(action, 'tier', 0)
        score = getattr(action, 'score', 0.0)
        desc = getattr(action, 'action_description', '')
        self._pending_writes.append(
            ("INSERT INTO mitigation_log (ts, tier, score, description) VALUES (?,?,?,?)",
             (ts, tier, score, desc))
        )
        self._maybe_flush()

    def log_correlation_score(self, score: float, timestamp: float):
        """Log a correlation score."""
        self._pending_writes.append(
            ("INSERT INTO scores (ts, score) VALUES (?,?)", (timestamp, score))
        )
        self._maybe_flush()

    def get_recent_scores(self, window_seconds: float) -> List[Tuple[float, float]]:
        """Get recent (timestamp, score) tuples."""
        self._flush()
        cutoff = time.time() - window_seconds
        cur = self.conn.cursor()
        cur.execute("SELECT ts, score FROM scores WHERE ts > ? ORDER BY ts", (cutoff,))
        return cur.fetchall()

    def get_event_count(self, since: float) -> int:
        """Count events since a timestamp."""
        self._flush()
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events WHERE ts > ?", (since,))
        return cur.fetchone()[0]

    def log_baseline_snapshot(self, feature_id: str, mean: float, variance: float):
        """Log a baseline state snapshot."""
        self._pending_writes.append(
            ("INSERT INTO baseline_snapshots (ts, feature_id, mean, variance) VALUES (?,?,?,?)",
             (time.time(), feature_id, mean, variance))
        )
        self._maybe_flush()

    def _maybe_flush(self):
        if time.time() - self._last_flush > self._flush_interval or len(self._pending_writes) > 100:
            self._flush()

    def _flush(self):
        if not self._pending_writes:
            return
        c = self.conn.cursor()
        for sql, params in self._pending_writes:
            c.execute(sql, params)
        self.conn.commit()
        self._pending_writes.clear()
        self._last_flush = time.time()

    def close(self):
        self._flush()
        self.conn.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
