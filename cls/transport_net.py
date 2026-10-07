# DLANVS

import json
import socket
import queue
import struct
import logging
import threading
from typing import Any, Optional
from cryptography import x509
from cls.crypto_manager import CryptoManager
from cls.voting_engine import VotingEngine
import dlanvs_fn as fn
import dlanvs_cfg as cfg

class Network:
    def __init__(self, args, crypto: CryptoManager, engine: VotingEngine):
        self.args = args
        self.crypto = crypto
        self.engine = engine
        self.stop_event = threading.Event()
        self.outgoing = queue.Queue(maxsize=5000)
        self.sock: Optional[socket.socket] = None
        self.lock = threading.Lock()
        self.local_ip = None

        if args.ip == "ipv4":
            if args.transport == "broadcast":
                self.destination = (args.broadcast, args.port)
            else:
                self.destination = (args.group, args.port)
        else:
            self.destination = (args.group, args.port, 0, args.interface_index)

    def setup(self):
        if self.args.ip == "ipv4":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.args.transport == "broadcast":
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.sock.bind(("", self.args.port))
            else:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(("", self.args.port))
                group = socket.inet_aton(self.args.group)
                interface = socket.inet_aton(self.args.interface or "0.0.0.0")
                mreq = group + interface
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("::", self.args.port))
            group = socket.inet_pton(socket.AF_INET6, self.args.group)
            mreq = group + struct.pack("@I", self.args.interface_index)
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self.sock.settimeout(0.5)

    def start(self):
        self.setup()
        threading.Thread(target=self._receiver, daemon=True, name="receiver").start()
        threading.Thread(target=self._sender, daemon=True, name="sender").start()
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        threading.Thread(target=self._digest_loop, daemon=True, name="digest").start()
        threading.Thread(target=self._status_loop, daemon=True, name="status").start()
        self.send_event(self.engine.hello_event())

    def stop(self):
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def send_event(self, event: dict[str, Any]):
        try:
            self.outgoing.put_nowait(event)
        except queue.Full:
            logging.warning("WARNING: outgoing queue full; packet dropped")            

    def _pack(self, event: dict[str, Any]) -> bytes:
        # Encrypt the payload, while keeping routing metadata visible.
        aad_obj = {
            "protocol_version": event["protocol_version"],
            "event_type": event["event_type"],
            "event_id": event["event_id"],
            "sender_id": event["sender_id"],
            "timestamp": event["timestamp"],
            "sequence": event["sequence"],
            "certificate": event["certificate"],
            "signature": event["signature"],
        }
        plaintext = fn.canonical(event["payload"])
        aad = fn.canonical(aad_obj)
        nonce, ciphertext = self.crypto.encrypt(plaintext, aad)
        wrapper = {
            "protocol_version": cfg.PROTOCOL_VERSION,
            "type": "EVENT",
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "sender_id": event["sender_id"],
            "timestamp": event["timestamp"],
            "sequence": event["sequence"],
            "certificate": event["certificate"],
            "signature": event["signature"],
            "nonce": fn.b64e(nonce),
            "ciphertext": fn.b64e(ciphertext),
        }
        raw = fn.canonical(wrapper)
        if len(raw) > self.args.max_packet:
            logging.error(
                f"packet too large ({len(raw)} > {self.args.max_packet}); "
                "reduce topic description/options or increase max packet carefully"
            )
        return raw

    def _unpack(self, raw: bytes) -> Optional[dict[str, Any]]:
        if len(raw) > self.args.max_packet:
            return None
        try:
            w = json.loads(raw.decode("utf-8"))
            if w.get("type") != "EVENT":
                return None
            event = {
                "protocol_version": w["protocol_version"],
                "event_type": w["event_type"],
                "event_id": w["event_id"],
                "sender_id": w["sender_id"],
                "timestamp": w["timestamp"],
                "sequence": w["sequence"],
                "certificate": w["certificate"],
                "signature": w["signature"],
            }
            cert = x509.load_der_x509_certificate(fn.b64d(event["certificate"]))
            if fn.participant_id_from_cert(cert) != event["sender_id"]:
                return None
            aad = fn.canonical(event)
            plaintext = self.crypto.decrypt(
                fn.b64d(w["nonce"]), fn.b64d(w["ciphertext"]), aad
            )
            logging.debug("_unpack: decrypted plaintext: "+str(plaintext))
            event["payload"] = json.loads(plaintext.decode("utf-8"))
            return event
        except Exception as exc:
            logging.error("_unpack : " + str(exc))
            return None

    def _sender(self):
        while not self.stop_event.is_set():
            try:
                event = self.outgoing.get(timeout=0.5)
                logging.debug(f"[SEND] event: {str(event)}")
            except queue.Empty:
                continue
            try:
                raw = self._pack(event)
                with self.lock:
                    if self.sock:
                        self.sock.sendto(raw, self.destination)
            except Exception as exc:
                logging.error(f"_sender: Network send error: {exc}")

    def _receiver(self):
        while not self.stop_event.is_set():
            try:
                data, _addr = self.sock.recvfrom(self.args.max_packet + 1)
            except socket.timeout:
                continue
            except OSError:
                logging.error(f"_receiver: OSError")
                break
            event = self._unpack(data)
            if not event:
                continue
            if event.get("event_type") in {"STATE_DIGEST", "STATE_REQUEST", "STATE_SNAPSHOT"}:
                ok, _reason = self.engine._validate_event_basic(event)
                if ok:
                    self._handle_control(event)
                continue
            ok, reason = self.engine.accept_event(event)
            if ok:
                # Update discovery information immediately for HELLO.
                if event["event_type"] == "HELLO":
                    p = self.engine.participants.get(event["sender_id"])
                    if p:
                        self.engine.db.upsert_participant(p)
                logging.debug(f"[RECV] {event['event_type']} "
                    f"{event['event_id'][:8]} from {event['sender_id'][:8]}"
                    f" event: {str(event)}"
                )
            elif reason not in ("duplicate event",):
                # Invalid packets are deliberately not printed verbosely.
                pass

    def _handle_control(self, event: dict[str, Any]):
        typ = event["event_type"]
        payload = event["payload"]
        if typ == "STATE_DIGEST":
            remote_hash = payload.get("state_hash")
            if remote_hash and remote_hash != self.engine.state_hash():
                self.send_control("STATE_REQUEST", {
                    "requester": self.crypto.participant_id,
                    "known_event_count": self.engine.db.event_count(),
                    "known_state_hash": self.engine.state_hash(),
                })
        elif typ == "STATE_REQUEST":
            # Synchronization remains network-wide; no unicast P2P connection.
            for e in self.engine.db.accepted_events():
                self.send_control("STATE_SNAPSHOT", {"event": e})
        elif typ == "STATE_SNAPSHOT":
            e = payload.get("event")
            if isinstance(e, dict):
                self.engine.accept_event(e)

    def _heartbeat_loop(self):
        while not self.stop_event.wait(self.args.heartbeat):
            self.send_event(self.engine.hello_event())

    def _digest_loop(self):
        while not self.stop_event.wait(self.args.digest_interval):
            payload = {
                "name": self.crypto.display_name,
                "event_count": self.engine.db.event_count(),
                "state_hash": self.engine.state_hash(),
            }
            self.send_control("STATE_DIGEST", payload)

    def _status_loop(self):
        while not self.stop_event.wait(2.0):
            self.engine.refresh_participant_status()

    def send_control(self, message_type: str, payload: dict[str, Any]):
        # Control packets use the same event mechanism, except STATE_DIGEST
        # is intentionally not a state-changing event. We still sign it.
        e = {
            "protocol_version": cfg.PROTOCOL_VERSION,
            "event_type": message_type,
            "event_id": fn.safe_uuid(),
            "sender_id": self.crypto.participant_id,
            "timestamp": fn.utc_ts(),
            "sequence": self.engine.next_sequence(),
            "payload": payload,
            "certificate": self.crypto.certificate_b64(),
        }
        e["signature"] = self.crypto.make_signature(e)
        try:
            raw = self._pack(e)
            # _pack uses the EVENT wrapper but preserves event_type.
            with self.lock:
                if self.sock:
                    self.sock.sendto(raw, self.destination)
        except Exception as exc:
            logging.error(f"Control send error: {exc}")
