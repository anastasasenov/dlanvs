# DLANVS

import argparse
import ipaddress

PROTOCOL_VERSION = 1
APP_NAME = "DLANVS"
APP_LONG_NAME = "Decentralized LAN Voting System"
DEFAULT_PORT = 37020
DEFAULT_IPV4_MULTICAST = "239.255.77.1"
DEFAULT_IPV6_MULTICAST = "ff02::1234"
DEFAULT_HEARTBEAT = 5.0
DEFAULT_ACTIVE_TIMEOUT = 15.0
DEFAULT_OFFLINE_TIMEOUT = 30.0
DEFAULT_DIGEST_INTERVAL = 10.0
DEFAULT_SYNC_INTERVAL = 20.0
DEFAULT_MAX_PACKET = 1200
MAX_SNAPSHOT_BYTES = 2_000_000
MAX_TOPIC_LIFETIME = 7 * 24 * 3600
MAX_VISIBILITY = 30 * 24 * 3600
ALLOWED_VOTES = {"YES", "NO", "ABSTAIN"}

CMD_INIT_CA = "init-ca"
CMD_INIT_NODE = "init-node"

def build_parser():

    p = argparse.ArgumentParser(description=APP_LONG_NAME)
    sub = p.add_subparsers(dest="command")

    ca = sub.add_parser(CMD_INIT_CA)
    ca.add_argument("--cert", default="ca.crt")
    ca.add_argument("--key", default="ca.key")

    node = sub.add_parser(CMD_INIT_NODE)
    node.add_argument("--name", required=True)
    node.add_argument("--ca", default="ca.crt")
    node.add_argument("--ca-key", default="ca.key")
    node.add_argument("--cert", default=None)
    node.add_argument("--key", default=None)

    # Runtime options live on the main parser so they can appear after/before command.
    p.add_argument("--ip", choices=["ipv4", "ipv6"], default="ipv4")
    p.add_argument("--transport", choices=["broadcast", "multicast"], default="multicast")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--broadcast", default="255.255.255.255")
    p.add_argument("--group", default=None)
    p.add_argument("--interface", default="0.0.0.0")
    p.add_argument("--interface-index", type=int, default=0)
    p.add_argument("--cert", default="node.crt")
    p.add_argument("--key", default="node.key")
    p.add_argument("--ca", default="ca.crt")
    p.add_argument("--group-key", default="group.key")
    p.add_argument("--key-password", default=None)
    p.add_argument("--db", default="dlanvs.sqlite3")
    p.add_argument("--heartbeat", type=float, default=DEFAULT_HEARTBEAT)
    p.add_argument("--active-timeout", type=float, default=DEFAULT_ACTIVE_TIMEOUT)
    p.add_argument("--offline-timeout", type=float, default=DEFAULT_OFFLINE_TIMEOUT)
    p.add_argument("--digest-interval", type=float, default=DEFAULT_DIGEST_INTERVAL)
    p.add_argument("--max-packet", type=int, default=DEFAULT_MAX_PACKET)
    return p


def validate_runtime_args(args):
    if args.ip == "ipv6" and args.transport == "broadcast":
        raise SystemExit("IPv6 does not support broadcast; use --transport multicast")
    if args.ip == "ipv4":
        if args.group is None:
            args.group = DEFAULT_IPV4_MULTICAST
    else:
        if args.group is None:
            args.group = DEFAULT_IPV6_MULTICAST
    if args.transport == "multicast":
        ip = ipaddress.ip_address(args.group)
        if not ip.is_multicast:
            raise SystemExit("--group must be a multicast address")
    if not (512 <= args.max_packet <= 65000):
        raise SystemExit("--max-packet must be between 512 and 65000")

