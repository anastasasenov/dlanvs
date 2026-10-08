# DLANVS

import uuid
import math
import threading
import logging
from typing import Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cls.store_db import Database
from cls.crypto_manager import CryptoManager
from cls.crypto_manager import Participant
import dlanvs_cfg as cfg
import dlanvs_fn as fn

class VotingEngine:
    def __init__(self, db: Database, crypto: CryptoManager):
        self.db = db
        self.crypto = crypto
        self.lock = threading.RLock()
        self.seq = self._load_sequence()
        self.participants: dict[str, Participant] = {
            p.participant_id: p for p in db.participants()
        }
        self.topics: dict[str, dict[str, Any]] = {
            t["topic_id"]: t for t in db.topics()
        }
        self.votes: dict[tuple[str, str], dict[str, Any]] = {
            (v["topic_id"], v["participant_id"]): v for v in db.votes()
        }
        self._rebuild_from_events()

    def _load_sequence(self) -> int:
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT value FROM metadata WHERE key='local_sequence'"
            ).fetchone()
        return int(row[0]) if row else 0

    def _save_sequence(self):
        with self.db.lock, self.db.conn:
            self.db.conn.execute("""
                INSERT OR REPLACE INTO metadata(key,value)
                VALUES('local_sequence',?)
            """, (str(self.seq),))

    def next_sequence(self) -> int:
        with self.lock:
            self.seq += 1
            self._save_sequence()
            return self.seq

    def _rebuild_from_events(self):
        with self.lock:
            self.participants = {}
            self.topics = {}
            self.votes = {}
            for event in self.db.accepted_events():
                self._apply(event, persist=False)

    def state_object(self) -> dict[str, Any]:
        with self.lock:
            participants = [
                {
                    "participant_id": p.participant_id,
                    "name": p.name,
                    "last_seen": round(p.last_seen, 3),
                    "sequence": p.sequence,
                    "status": p.status,
                }
                for p in sorted(
                    self.participants.values(),
                    key=lambda x: x.participant_id,
                )
            ]
            topics = []
            for t in sorted(self.topics.values(), key=lambda x: x["topic_id"]):
                votes = []
                for (tid, pid), v in sorted(self.votes.items()):
                    if tid == t["topic_id"]:
                        votes.append({
                            "participant_id": pid,
                            "vote": v["vote"],
                            "event_id": v["event_id"],
                        })
                x = dict(t)
                x["votes"] = votes
                topics.append(x)
            return {"participants": participants, "topics": topics}

    def state_hash(self) -> str:
        return fn.canonical_hash(self.state_object())

    def _validate_event_basic(self, event: dict[str, Any]) -> tuple[bool, str]:
        required = {
            "protocol_version", "event_type", "event_id", "sender_id",
            "timestamp", "sequence", "payload", "signature", "certificate"
        }
        if not required.issubset(event):
            return False, "missing fields"
        if event["protocol_version"] != cfg.PROTOCOL_VERSION:
            return False, "unsupported protocol version"
        try:
            uuid.UUID(event["event_id"])
        except Exception:
            return False, "invalid event id"
        if not isinstance(event["sender_id"], str) or len(event["sender_id"]) != 64:
            return False, "invalid sender id"
        if not isinstance(event["sequence"], int) or event["sequence"] < 1:
            return False, "invalid sequence"
        if abs(fn.utc_ts() - float(event["timestamp"])) > 24 * 3600:
            return False, "timestamp outside allowed window"
        try:
            cert = x509.load_der_x509_certificate(fn.b64d(event["certificate"]))
        except Exception:
            return False, "invalid certificate"
        pid = fn.participant_id_from_cert(cert)
        if pid != event["sender_id"]:
            return False, "sender id does not match certificate"
        if not fn.valid_certificate(cert, self.crypto.ca):
            return False, "untrusted certificate"
        if not self.crypto.verify_event_signature(cert, event):
            return False, "invalid signature"
        return True, ""

    def accept_event(self, event: dict[str, Any], persist=True) -> tuple[bool, str]:
        with self.lock:
            eid = event.get("event_id")
            if not eid:
                return False, "missing event id"
            if self.db.has_event(eid):
                return False, "duplicate event"
            ok, reason = self._validate_event_basic(event)
            if not ok:
                if persist:
                    self.db.insert_event(event, False, reason)
                return False, reason

            # Sender sequence is monotonic. We do not require contiguous
            # sequences because UDP can lose packets.
            existing = [
                e for e in self.db.all_events()
                if e.get("sender_id") == event["sender_id"]
            ]
            if any(
                int(e.get("sequence", 0)) == int(event["sequence"])
                for e in existing
            ):
                if persist:
                    self.db.insert_event(event, False, "duplicate sender sequence")
                return False, "duplicate sender sequence"

            ok, reason = self._validate_semantics(event)
            if not ok:
                if persist:
                    self.db.insert_event(event, False, reason)
                return False, reason

            if persist:
                self.db.insert_event(event, True)
            self._apply(event, persist=persist)
            return True, "accepted"

    def _validate_semantics(self, e: dict[str, Any]) -> tuple[bool, str]:
        typ = e["event_type"]
        p = e["payload"]
        sender = e["sender_id"]

        if typ == "HELLO":
            return True, ""

        if typ == "TOPIC_CREATED":
            required = {
                "topic_id", "title", "description", "created_at",
                "voting_deadline", "visibility_deadline", "quorum_percent",
                "eligible_participants", "eligible_hash", "options"
            }
            if not required.issubset(p):
                return False, "invalid topic fields"
            if p["topic_id"] in self.topics:
                return False, "topic already exists"
            eligible = sorted(set(p["eligible_participants"]))
            if not eligible or sender not in eligible:
                return False, "creator not in eligible set"
            if fn.canonical_hash(eligible) != p["eligible_hash"]:
                return False, "eligible participant hash mismatch"
            q = float(p["quorum_percent"])
            if not 0 < q <= 100:
                return False, "invalid quorum"
            now = float(p["created_at"])
            deadline = float(p["voting_deadline"])
            visibility = float(p["visibility_deadline"])
            if deadline <= now or visibility < deadline:
                return False, "invalid topic deadlines"
            if deadline - now > cfg.MAX_TOPIC_LIFETIME:
                return False, "topic lifetime too long"
            if visibility - deadline > cfg.MAX_VISIBILITY:
                return False, "visibility lifetime too long"
            options = p["options"]
            if not isinstance(options, list) or not 2 <= len(options) <= 32:
                return False, "invalid options"
            if len(set(options)) != len(options):
                return False, "duplicate options"
            return True, ""

        if typ == "VOTE_CAST":
            required = {"topic_id", "participant_id", "vote"}
            if not required.issubset(p):
                return False, "invalid vote fields"
            if p["participant_id"] != sender:
                return False, "vote sender mismatch"
            topic = self.topics.get(p["topic_id"])
            if not topic:
                return False, "unknown topic"
            if sender not in topic["eligible_participants"]:
                return False, "participant not eligible"
            if p["vote"] not in topic["options"]:
                return False, "invalid vote option"
            if (p["topic_id"], sender) in self.votes:
                return False, "participant already voted"
            if float(e["timestamp"]) > float(topic["voting_deadline"]) + 5:
                return False, "vote arrived after deadline"
            return True, ""

        return False, f"unknown event type: {typ}"

    def _apply(self, e: dict[str, Any], persist=True):
        typ = e["event_type"]
        p = e["payload"]

        if typ == "HELLO":
            try:
                cert = x509.load_der_x509_certificate(fn.b64d(e["certificate"]))
                participant = Participant(
                    e["sender_id"],
                    fn.certificate_name(cert),
                    cert.public_bytes(serialization.Encoding.DER),
                    float(e["timestamp"]),
                    int(e["sequence"]),
                    "ACTIVE",
                )
                self.participants[e["sender_id"]] = participant
                if persist:
                    self.db.upsert_participant(participant)
            except Exception as exc:
                logging.warning("_apply: " + str(exc))
                return

        elif typ == "TOPIC_CREATED":
            self.topics[p["topic_id"]] = dict(p)
            if persist:
                self.db.save_topic(p)

        elif typ == "VOTE_CAST":
            key = (p["topic_id"], p["participant_id"])
            if key not in self.votes:
                self.votes[key] = {
                    "topic_id": p["topic_id"],
                    "participant_id": p["participant_id"],
                    "vote": p["vote"],
                    "event_id": e["event_id"],
                    "timestamp": e["timestamp"],
                }
                if persist:
                    self.db.save_vote(self.votes[key])

    def make_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        event = {
            "protocol_version": cfg.PROTOCOL_VERSION,
            "event_type": event_type,
            "event_id": fn.safe_uuid(),
            "sender_id": self.crypto.participant_id,
            "timestamp": fn.utc_ts(),
            "sequence": self.next_sequence(),
            "payload": payload,
            "certificate": self.crypto.certificate_b64(),
        }
        event["signature"] = self.crypto.make_signature(event)
        return event

    def create_topic(self, title: str, description: str,
                     duration_seconds: int, visibility_seconds: int,
                     quorum_percent: float, options: list[str]) -> dict[str, Any]:
        with self.lock:
            eligible = sorted(
                p.participant_id
                for p in self.participants.values()
                if p.status == "ACTIVE"
            )
            if self.crypto.participant_id not in eligible:
                eligible.append(self.crypto.participant_id)
                eligible.sort()
            if not eligible:
                raise ValueError("No eligible participants discovered")
            created = fn.utc_ts()
            deadline = created + duration_seconds
            visibility = deadline + visibility_seconds
            payload = {
                "topic_id": fn.safe_uuid(),
                "title": title.strip(),
                "description": description.strip(),
                "created_at": created,
                "voting_deadline": deadline,
                "visibility_deadline": visibility,
                "quorum_percent": float(quorum_percent),
                "eligible_participants": eligible,
                "eligible_hash": fn.canonical_hash(eligible),
                "options": options,
            }
            e = self.make_event("TOPIC_CREATED", payload)
            ok, reason = self.accept_event(e)
            if not ok:
                logging.error("create_topic: " + reason)
                raise RuntimeError(reason)
            return e

    def cast_vote(self, topic_id: str, vote: str) -> dict[str, Any]:
        with self.lock:
            topic = self.topics.get(topic_id)
            if not topic:
                raise ValueError("Unknown topic")
            if (topic["topic_id"], self.crypto.participant_id) in self.votes:
                raise ValueError("Already voted")
            if self.crypto.participant_id not in topic["eligible_participants"]:
                raise ValueError("Not eligible")
            if fn.utc_ts() > float(topic["voting_deadline"]):
                raise ValueError("Voting deadline has passed")
            if vote not in topic["options"]:
                raise ValueError(f"Vote must be one of: {', '.join(topic['options'])}")
            e = self.make_event("VOTE_CAST", {
                "topic_id": topic_id,
                "participant_id": self.crypto.participant_id,
                "vote": vote,
            })
            ok, reason = self.accept_event(e)
            if not ok:
                logging.error("cast_vote: " + reason)
                raise RuntimeError(reason)
            return e

    def hello_event(self) -> dict[str, Any]:
        return self.make_event("HELLO", {
            "name": self.crypto.display_name,
            "certificate_fingerprint": fn.cert_fingerprint(self.crypto.cert),
        })

    def result(self, topic_id: str) -> dict[str, Any]:
        with self.lock:
            t = self.topics[topic_id]
            eligible = len(t["eligible_participants"])
            required = math.ceil(eligible * float(t["quorum_percent"]) / 100.0)
            rows = [
                v for (tid, _), v in self.votes.items()
                if tid == topic_id
            ]
            counts = {o: 0 for o in t["options"]}
            for v in rows:
                counts[v["vote"]] += 1
            valid = len(rows) >= required
            closed = fn.utc_ts() >= float(t["voting_deadline"]) or len(rows) >= eligible
            winner = None
            if closed and valid:
                winner = max(
                    counts.items(),
                    key=lambda kv: (kv[1], -t["options"].index(kv[0]))
                )[0]
            return {
                "topic_id": topic_id,
                "votes": len(rows),
                "eligible": eligible,
                "quorum_required": required,
                "quorum_percent": t["quorum_percent"],
                "quorum_met": valid,
                "closed": closed,
                "counts": counts,
                "winner": winner,
            }

    def topic_status(self, topic: dict[str, Any]) -> str:
        now = fn.utc_ts()
        rows = [
            v for (tid, _), v in self.votes.items()
            if tid == topic["topic_id"]
        ]
        if len(rows) >= len(topic["eligible_participants"]):
            return "COMPLETED"
        if now < topic["voting_deadline"]:
            return "ACTIVE"
        return "EXPIRED"

    def refresh_participant_status(self, active_timeout=cfg.DEFAULT_ACTIVE_TIMEOUT,
                                   offline_timeout=cfg.DEFAULT_OFFLINE_TIMEOUT):
        now = fn.utc_ts()
        with self.lock:
            for p in self.participants.values():
                age = now - p.last_seen
                new_status = (
                    "ACTIVE" if age <= active_timeout
                    else "SUSPECT" if age <= offline_timeout
                    else "OFFLINE"
                )
                if p.status != new_status:
                    p.status = new_status
                    self.db.upsert_participant(p)
