# DLANVS

import argparse
import base64
import cmd
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import queue
import secrets
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time
import uuid
import logging
from pathlib import Path
from typing import Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from cls.voting_engine import VotingEngine
from cls.store_db import Database
from cls.crypto_manager import CryptoManager
from cls.transport_net import Network
import dlanvs_cfg as cfg


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_ts() -> float:
    return utc_now().timestamp()


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha256(canonical(obj))


def safe_uuid() -> str:
    return str(uuid.uuid4())


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_public_key_bytes(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def participant_id_from_cert(cert: x509.Certificate) -> str:
    return sha256(cert_public_key_bytes(cert))


def certificate_name(cert: x509.Certificate) -> str:
    try:
        vals = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return vals[0].value if vals else "unknown"
    except Exception:
        return "unknown"


def load_cert(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_private_key(path: str, password: Optional[str] = None):
    data = Path(path).read_bytes()
    pwd = password.encode() if password else None
    return serialization.load_pem_private_key(data, password=pwd)


def save_pem(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)


def sign(private_key, data: bytes) -> bytes:
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("This implementation expects Ed25519 private keys")
    return private_key.sign(data)


def verify(cert: x509.Certificate, signature: bytes, data: bytes) -> bool:
    try:
        cert.public_key().verify(signature, data)
        return True
    except Exception:
        return False


def verify_cert_signed_by(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        if cert.issuer != ca.subject:
            return False
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        # Ed25519 certificates have no signature_hash_algorithm.
        try:
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        except Exception:
            return False


def valid_certificate(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    now = utc_now()
    try:
        # cryptography versions differ in these properties; support both.
        nbf = getattr(cert, "not_valid_before_utc", None)
        naf = getattr(cert, "not_valid_after_utc", None)
        if nbf is None:
            nbf = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        if naf is None:
            naf = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
        return (
            nbf <= now <= naf
            and cert.subject != ca.subject
            and verify_cert_signed_by(cert, ca)
        )
    except Exception:
        return False
    
def generate_ca(out_cert: str, out_key: str, common_name="DLANVS Root CA"):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    save_pem(out_key, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    save_pem(out_cert, cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created CA certificate: {out_cert}")
    print(f"Created CA private key:    {out_key}")


def generate_node(name: str, ca_cert_path: str, ca_key_path: str,
                  out_cert: str, out_key: str):
    ca_cert = load_cert(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, None)
    )
    save_pem(out_key, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    save_pem(out_cert, cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created node certificate: {out_cert}")
    print(f"Created node private key: {out_key}")


def ensure_group_key(path: str):
    p = Path(path)
    if not p.exists():
        p.write_text(b64e(secrets.token_bytes(32)))
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        print(f"Created group key: {path}")

def setupLogging(
    log_file: str = None,
    log_level: str = "INFO"):

    h = logging.StreamHandler()
    if log_file:
        h = logging.FileHandler(log_file)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    h.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(h)
    logging.info(cfg.APP_NAME + " starting ...")

def run_gui(engine: VotingEngine, network: Network):
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog

    root = tk.Tk()
    root.title(f"{cfg.APP_NAME} - {engine.crypto.display_name}")
    root.geometry("1000x700")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")

    ttk.Label(
        top,
        text=f"Participant: {engine.crypto.display_name} | "
             f"ID: {engine.crypto.participant_id[:16]}",
    ).pack(side="left")
    status_var = tk.StringVar(value="Running")
    ttk.Label(top, textvariable=status_var).pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=8, pady=8)

    topics_frame = ttk.Frame(notebook, padding=8)
    participants_frame = ttk.Frame(notebook, padding=8)
    info_frame = ttk.Frame(notebook, padding=8)
    notebook.add(topics_frame, text="Topics")
    notebook.add(participants_frame, text="Participants")
    notebook.add(info_frame, text="Status")

    columns = ("id", "status", "title", "votes", "quorum", "deadline")
    tree = ttk.Treeview(topics_frame, columns=columns, show="headings", height=20)
    for c, width in [
        ("id", 150), ("status", 100), ("title", 250),
        ("votes", 80), ("quorum", 100), ("deadline", 200)
    ]:
        tree.heading(c, text=c.title())
        tree.column(c, width=width)
    tree.pack(fill="both", expand=True)

    buttons = ttk.Frame(topics_frame)
    buttons.pack(fill="x", pady=8)

    def create_topic():
        title = simpledialog.askstring("Create topic", "Title:", parent=root)
        if not title:
            return
        dur = simpledialog.askinteger(
            "Create topic", "Voting duration (seconds):",
            parent=root, initialvalue=300, minvalue=10, maxvalue=cfg.MAX_TOPIC_LIFETIME
        )
        if dur is None:
            return
        vis = simpledialog.askinteger(
            "Create topic", "Visibility after deadline (seconds):",
            parent=root, initialvalue=600, minvalue=0, maxvalue=cfg.MAX_VISIBILITY
        )
        if vis is None:
            return
        quorum = simpledialog.askfloat(
            "Create topic", "Quorum percentage:",
            parent=root, initialvalue=50.0, minvalue=0.1, maxvalue=100.0
        )
        if quorum is None:
            return
        opts = simpledialog.askstring(
            "Create topic", "Options, comma separated:",
            parent=root, initialvalue="YES,NO"
        )
        if not opts:
            return
        options = [x.strip() for x in opts.split(",") if x.strip()]
        try:
            e = engine.create_topic(title, "", dur, vis, quorum, options)
            network.send_event(e)
            refresh()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def selected_topic():
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Vote", "Select a topic first.")
            return None
        return tree.item(sel[0], "values")[0]

    def vote():
        tid = selected_topic()
        if not tid:
            return
        topic = engine.topics[tid]
        option = simpledialog.askstring(
            "Vote", f"Options: {', '.join(topic['options'])}\nEnter option:",
            parent=root
        )
        if not option:
            return
        try:
            e = engine.cast_vote(tid, option.strip())
            network.send_event(e)
            refresh()
        except Exception as exc:
            messagebox.showerror("Vote rejected", str(exc))

    def result():
        tid = selected_topic()
        if not tid:
            return
        r = engine.result(tid)
        messagebox.showinfo("Result", json.dumps(r, indent=2))

    ttk.Button(buttons, text="Create Topic", command=create_topic).pack(side="left", padx=4)
    ttk.Button(buttons, text="Vote", command=vote).pack(side="left", padx=4)
    ttk.Button(buttons, text="Result", command=result).pack(side="left", padx=4)

    pcols = ("name", "id", "status", "last")
    ptree = ttk.Treeview(participants_frame, columns=pcols, show="headings")
    for c, width in [("name", 220), ("id", 260), ("status", 120), ("last", 250)]:
        ptree.heading(c, text=c.title())
        ptree.column(c, width=width)
    ptree.pack(fill="both", expand=True)

    info = tk.Text(info_frame, wrap="word")
    info.pack(fill="both", expand=True)

    def get_selected_pos():
        nRet = -1
        ids = tree.selection()
        if len( ids ) == 1:
            all_ids = tree.get_children()
            for i in range(0, len(all_ids)):
                if ids[0] == all_ids[i]:
                    nRet = i
                    break
        return nRet

    def set_selected_pos(nPos):
        all_ids = tree.get_children()
        if nPos < len(all_ids) and nPos >= 0:
            tree.selection_set(all_ids[nPos])

    def refresh():
        sel_pos = get_selected_pos()
        engine.refresh_participant_status()
        for item in tree.get_children():
            tree.delete(item)
        for t in sorted(engine.topics.values(), key=lambda x: x["topic_id"]):
            r = engine.result(t["topic_id"])
            tree.insert("", "end", values=(
                t["topic_id"], engine.topic_status(t), t["title"],
                f"{r['votes']}/{r['eligible']}",
                f"{r['votes']}/{r['quorum_required']}",
                iso(t["voting_deadline"]),
            ))

        for item in ptree.get_children():
            ptree.delete(item)
        for p in sorted(engine.participants.values(), key=lambda x: x.name):
            ptree.insert("", "end", values=(
                p.name, p.participant_id[:32], p.status, iso(p.last_seen)
            ))

        info.delete("1.0", "end")
        info.insert("end", f"Participant: {engine.crypto.display_name}\n")
        info.insert("end", f"ID: {engine.crypto.participant_id}\n")
        info.insert("end", f"Events: {engine.db.event_count()}\n")
        info.insert("end", f"State hash: {engine.state_hash()}\n")
        info.insert("end", f"Topics: {len(engine.topics)}\n")
        info.insert("end", f"Participants: {len(engine.participants)}\n")
        status_var.set(f"Running | {len(engine.participants)} participants")

        set_selected_pos( sel_pos )

        root.after(2000, refresh)

    def on_close():
        network.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh()
    root.mainloop()
