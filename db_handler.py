"""
db_handler.py
-------------
SQLite persistence layer for the NIDS alert store.

Provides a small, thread-safe wrapper around an `alerts` table used by
ids_core.py (writer) and app.py / dashboard.html (readers).

Author : Rithika U
Project: NIDS - Network Intrusion Detection System
"""

import sqlite3
import threading
from datetime import datetime


class DBHandler:
    """Thread-safe SQLite handler for IDS alerts."""

    def __init__(self, db_path="alerts.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    def _get_conn(self):
        # check_same_thread=False because the sniffer thread and the
        # Flask request thread both use this handler.
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT    NOT NULL,
                        alert_type  TEXT    NOT NULL,
                        src_ip      TEXT,
                        dst_ip      TEXT,
                        description TEXT,
                        severity    TEXT
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts (timestamp)
                    """
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------
    def insert_alert(self, alert_type, src_ip, dst_ip, description, severity):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO alerts
                        (timestamp, alert_type, src_ip, dst_ip, description, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.now().isoformat(timespec="seconds"),
                        alert_type,
                        src_ip,
                        dst_ip,
                        description,
                        severity,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def clear_alerts(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM alerts")
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------
    def get_alerts(self, limit=100, severity=None):
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()
                if severity:
                    cur.execute(
                        """
                        SELECT id, timestamp, alert_type, src_ip, dst_ip,
                               description, severity
                        FROM alerts
                        WHERE severity = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (severity, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT id, timestamp, alert_type, src_ip, dst_ip,
                               description, severity
                        FROM alerts
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    )
                rows = cur.fetchall()
            finally:
                conn.close()

        columns = ("id", "timestamp", "alert_type", "src_ip", "dst_ip",
                    "description", "severity")
        return [dict(zip(columns, row)) for row in rows]

    def get_alert_counts(self):
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.cursor()

                cur.execute("SELECT COUNT(*) FROM alerts")
                total = cur.fetchone()[0]

                cur.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                )
                by_severity = dict(cur.fetchall())

                cur.execute(
                    "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"
                )
                by_type = dict(cur.fetchall())
            finally:
                conn.close()

        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
        }
