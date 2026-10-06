# DLANVS

import threading
import sqlite3
from typing import Any, Optional
from cls.crypto_manager import Participant

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._schema()

    def _schema(self):
        with self.conn:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_sequence INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                event_json TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                rejection_reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_sender
            ON events(sender_id, sender_sequence);

            CREATE TABLE IF NOT EXISTS participants (
                participant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                certificate_der BLOB NOT NULL,
                last_seen REAL NOT NULL,
                sequence INTEGER NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS topics (
                topic_id TEXT PRIMARY KEY,
                topic_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS votes (
                topic_id TEXT NOT NULL,
                participant_id TEXT NOT NULL,
                vote TEXT NOT NULL,
                event_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                PRIMARY KEY(topic_id, participant_id)
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

    def has_event(self, event_id: str) -> bool:
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            return row is not None

    def event_count(self) -> int:
        with self.lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def insert_event(self, event: dict[str, Any], accepted: bool,
                     reason: Optional[str] = None):
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR IGNORE INTO events
                (event_id,event_type,sender_id,sender_sequence,timestamp,
                 event_json,accepted,rejection_reason)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                event["event_id"], event["event_type"], event["sender_id"],
                int(event.get("sequence", 0)), float(event["timestamp"]),
                json.dumps(event, sort_keys=True, separators=(",", ":")),
                1 if accepted else 0, reason,
            ))

    def accepted_events(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("""
                SELECT event_json FROM events
                WHERE accepted=1
                ORDER BY timestamp, sender_id, sender_sequence, event_id
            """).fetchall()
        return [json.loads(r[0]) for r in rows]

    def all_events(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("""
                SELECT event_json FROM events
                ORDER BY timestamp, sender_id, sender_sequence, event_id
            """).fetchall()
        return [json.loads(r[0]) for r in rows]

    def replace_events(self, events: list[dict[str, Any]]):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM events")
            for e in events:
                self.conn.execute("""
                    INSERT INTO events
                    (event_id,event_type,sender_id,sender_sequence,timestamp,
                     event_json,accepted,rejection_reason)
                    VALUES (?,?,?,?,?,?,1,NULL)
                """, (
                    e["event_id"], e["event_type"], e["sender_id"],
                    int(e.get("sequence", 0)), float(e["timestamp"]),
                    json.dumps(e, sort_keys=True, separators=(",", ":")),
                ))

    def clear_derived(self):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM topics")
            self.conn.execute("DELETE FROM votes")
            self.conn.execute("DELETE FROM participants")

    def upsert_participant(self, p: Participant):
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT INTO participants
                (participant_id,name,certificate_der,last_seen,sequence,status)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(participant_id) DO UPDATE SET
                    name=excluded.name,
                    certificate_der=excluded.certificate_der,
                    last_seen=excluded.last_seen,
                    sequence=excluded.sequence,
                    status=excluded.status
            """, (
                p.participant_id, p.name, p.certificate_der,
                p.last_seen, p.sequence, p.status,
            ))

    def participants(self) -> list[Participant]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM participants ORDER BY name, participant_id"
            ).fetchall()
        return [
            Participant(
                r["participant_id"], r["name"], r["certificate_der"],
                r["last_seen"], r["sequence"], r["status"]
            ) for r in rows
        ]

    def save_topic(self, topic: dict[str, Any]):
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO topics(topic_id,topic_json)
                VALUES (?,?)
            """, (topic["topic_id"], json.dumps(topic, sort_keys=True)))

    def topics(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT topic_json FROM topics ORDER BY topic_id"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def save_vote(self, vote: dict[str, Any]):
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR IGNORE INTO votes
                (topic_id,participant_id,vote,event_id,timestamp)
                VALUES (?,?,?,?,?)
            """, (
                vote["topic_id"], vote["participant_id"], vote["vote"],
                vote["event_id"], vote["timestamp"],
            ))

    def votes(self, topic_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self.lock:
            if topic_id:
                rows = self.conn.execute("""
                    SELECT * FROM votes WHERE topic_id=?
                    ORDER BY participant_id
                """, (topic_id,)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM votes ORDER BY topic_id, participant_id"
                ).fetchall()
        return [dict(r) for r in rows]
