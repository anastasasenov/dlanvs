# DLANVS

import cmd
from cls.voting_engine import VotingEngine
from cls.transport_net import Network

class Console(cmd.Cmd):
    intro = (
        "\nDLANVS CLI. Type 'help' for commands, 'topics' to list topics, "
        "'participants' to list nodes.\n"
    )
    prompt = "dlanvs> "

    def __init__(self, engine: VotingEngine, network: Network):
        super().__init__()
        self.engine = engine
        self.network = network

    def do_participants(self, arg):
        """List discovered participants."""
        self.engine.refresh_participant_status()
        print(f"{'NAME':20} {'ID':16} {'STATUS':10} LAST SEEN")
        for p in self.engine.participants.values():
            print(
                f"{p.name[:20]:20} {p.participant_id[:16]:16} "
                f"{p.status:10} {iso(p.last_seen)}"
            )

    def do_topics(self, arg):
        """List topics."""
        for t in self.engine.topics.values():
            r = self.engine.result(t["topic_id"])
            print(
                f"{t['topic_id']} | {self.engine.topic_status(t):9} | "
                f"{t['title']} | votes {r['votes']}/{r['eligible']} | "
                f"quorum {r['votes']}/{r['quorum_required']}"
            )

    def do_create(self, arg):
        """create TITLE | duration_seconds | visibility_seconds | quorum_percent | OPTION1,OPTION2"""
        try:
            parts = [x.strip() for x in arg.split("|")]
            if len(parts) != 5:
                raise ValueError("format: create TITLE|duration|visibility|quorum|OPTION1,OPTION2")
            title, duration, visibility, quorum, options = parts
            options = [x.strip() for x in options.split(",") if x.strip()]
            if not title:
                raise ValueError("empty title")
            if len(options) < 2:
                raise ValueError("at least two options")
            e = self.engine.create_topic(
                title, "", int(duration), int(visibility), float(quorum), options
            )
            self.network.send_event(e)
            print(f"Created topic: {e['payload']['topic_id']}")
        except Exception as exc:
            print(f"ERROR: {exc}")

    def do_vote(self, arg):
        """vote TOPIC_ID OPTION"""
        try:
            parts = arg.split()
            if len(parts) != 2:
                raise ValueError("format: vote TOPIC_ID OPTION")
            e = self.engine.cast_vote(parts[0], parts[1])
            self.network.send_event(e)
            print("Vote accepted locally and broadcast.")
        except Exception as exc:
            print(f"ERROR: {exc}")

    def do_result(self, arg):
        """result TOPIC_ID"""
        try:
            r = self.engine.result(arg.strip())
            print(json.dumps(r, indent=2))
        except Exception as exc:
            print(f"ERROR: {exc}")

    def do_status(self, arg):
        """Show local node status."""
        print("Participant:", self.engine.crypto.display_name)
        print("ID:", self.engine.crypto.participant_id)
        print("Events:", self.engine.db.event_count())
        print("State hash:", self.engine.state_hash())

    def do_sync(self, arg):
        """Broadcast a state digest request."""
        self.network.send_control("STATE_DIGEST", {
            "name": self.engine.crypto.display_name,
            "event_count": self.engine.db.event_count(),
            "state_hash": self.engine.state_hash(),
        })
        print("State digest broadcast.")

    def do_quit(self, arg):
        """Exit."""
        return True

    def do_exit(self, arg):
        """Exit."""
        return True

    def emptyline(self):
        pass
