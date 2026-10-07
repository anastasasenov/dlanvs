#
# Decentralized LAN Voting System
#
#   This is a LAN/serverless experimental implementation

import sys
import signal
import ipaddress
from pathlib import Path
import dlanvs_cfg as cfg
import dlanvs_fn as fn
from cls.voting_engine import VotingEngine
from cls.store_db import Database
from cls.crypto_manager import CryptoManager
from cls.transport_net import Network
from cls.vote_console import Console

def main():

    parser = cfg.build_parser()
    args = parser.parse_args()
    fn.setupLogging(args.log_file, args.log_level, str(args))

    if args.command == cfg.CMD_INIT_CA:
        fn.generate_ca(args.cert if hasattr(args, "cert") else "ca.crt",
                    args.key if hasattr(args, "key") else "ca.key")
        return

    if args.command == cfg.CMD_INIT_NODE:
        cert = args.cert or f"{args.name}.crt"
        key = args.key or f"{args.name}.key"
        fn.generate_node(args.name, args.ca, args.ca_key, cert, key)
        return

    cfg.validate_runtime_args(args)

    if not Path(args.cert).exists():
        raise SystemExit(f"Certificate not found: {args.cert}")
    if not Path(args.key).exists():
        raise SystemExit(f"Private key not found: {args.key}")
    if not Path(args.ca).exists():
        raise SystemExit(f"CA certificate not found: {args.ca}")

    fn.ensure_group_key(args.group_key)

    crypto = CryptoManager(
        args.cert, args.key, args.ca, args.key_password, args.group_key
    )
    db = Database(args.db)
    engine = VotingEngine(db, crypto)
    network = Network(args, crypto, engine)

    try:
        network.start()
    except Exception as exc:
        raise SystemExit(f"Unable to start network: {exc}")

    def stop_handler(signum, frame):
        network.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, stop_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_handler)

    print("." * 70)
    print("DLANVS started")
    print(f"Participant : {crypto.display_name}")
    print(f"ID          : {crypto.participant_id}")
    print(f"IP          : {args.ip}")
    print(f"Transport   : {args.transport}")
    print(f"Group       : {args.group}")
    print(f"Port        : {args.port}")
    print(f"Database    : {args.db}")
    print(f"State hash  : {engine.state_hash()}")
    print("." * 70)

    # GUI ( Tkinter ) is optional. TUI default ( terminal CLI )
    if not sys.stdin.isatty():
        fn.run_gui(engine, network)
    else:
        try:
            Console(engine, network).cmdloop()
        finally:
            network.stop()
