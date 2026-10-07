## Decentralized Local Network Voting System
![AI Assisted](https://shields.io)

This is an experimenta voting system written in Python. The system operates entirely within a Local Area Network (LAN) without a central server.

### Architecture

    UI (Terminal/Tkinter) - Voting Module - Crypto Module - Network Module (ipv4/6)

### Prerequisites

$ pip install cryptography 

### Command Line Arguments

The script utilizes argparse for flexible CLI configuration:

    positional arguments:

        {init-ca,init-node}

    optional arguments:

        --ip {ipv4,ipv6}
        --transport {broadcast,multicast}
        --port PORT
        --broadcast BROADCAST
        --group GROUP
        --interface INTERFACE
        --interface-index INTERFACE_INDEX
        --cert CERT
        --key KEY
        --ca CA
        --group-key GROUP_KEY
        --key-password KEY_PASSWORD
        --db DB
        --heartbeat HEARTBEAT
        --active-timeout ACTIVE_TIMEOUT
        --offline-timeout OFFLINE_TIMEOUT
        --digest-interval DIGEST_INTERVAL
        --max-packet MAX_PACKET

### Usage

    $ python3 ./dlanvs init-ca
    $ python3 ./dlanvs init-node --name ivo --ca ca.crt --ca-key ca.key
    $ python3 ./dlanvs --ip ipv4 --transport multicast --cert ivo.crt --key ivo.key --ca ca.crt

### Notes

Since this project is experimental, multiple options can be trialed.

    extend voting system on WAN
    improve security / blockchain impl
    improve performance
    add discussion topics
    add private messages
    add unit/automation tests

### License

This project is open-source and available under the MIT License.
