"""The eight lab stories. Timestamps are fixed so the tests stay repeatable."""

from datetime import datetime, timedelta, timezone

from dfir_soc.detect import EICAR_SHA256, LabEvent

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=timezone.utc)
HOME_COUNTRIES = {
    "alice": {"DE"},
    "bob": {"US"},
    "carol": {"US"},
    "dave": {"DE"},
    "eve": {"DE"},
}


def _at(minutes):
    return T0 + timedelta(minutes=minutes)


def login(minutes, user, result, srcip, country, service="ssh"):
    return LabEvent(_at(minutes), "login", result, user, srcip, country, service)


def file_event(minutes, user, result, path):
    return LabEvent(
        _at(minutes), "file", result, user, "10.0.0.20", "DE", "sysmon",
        sha256=EICAR_SHA256, path=path,
    )


class Scenario:
    def __init__(self, name, summary, events, rule_ids):
        self.name = name
        self.summary = summary
        self.events = events
        self.rule_ids = set(rule_ids)


SCENARIOS = [
    Scenario(
        "impossible-travel",
        "Alice succeeds in Germany and, half an hour later, in Brazil.",
        [
            login(0, "alice", "success", "203.0.113.10", "DE"),
            login(30, "alice", "success", "198.51.100.20", "BR"),
        ],
        {"100101"},
    ),
    Scenario(
        "failures-then-success",
        "Six failures for Bob are followed by a success from the same address.",
        [
            login(0, "bob", "failure", "203.0.113.40", "US"),
            login(1, "bob", "failure", "203.0.113.40", "US"),
            login(1, "bob", "failure", "203.0.113.40", "US"),
            login(2, "bob", "failure", "203.0.113.40", "US"),
            login(2, "bob", "failure", "203.0.113.40", "US"),
            login(3, "bob", "failure", "203.0.113.40", "US"),
            login(4, "bob", "success", "203.0.113.40", "US"),
        ],
        {"100202"},
    ),
    Scenario(
        "failure-ip-then-other-success",
        "Carol fails three times from one address and then succeeds from another.",
        [
            login(0, "carol", "failure", "203.0.113.8", "US"),
            login(1, "carol", "failure", "203.0.113.8", "US"),
            login(2, "carol", "failure", "203.0.113.8", "US"),
            login(3, "carol", "success", "198.51.100.9", "US"),
        ],
        {"100301"},
    ),
    Scenario(
        "vpn-new-source",
        "Dave's VPN login fails from the office and then succeeds from a new address.",
        [
            login(0, "dave", "failure", "203.0.113.5", "DE", service="vpn"),
            login(2, "dave", "failure", "203.0.113.5", "DE", service="vpn"),
            login(4, "dave", "success", "198.51.100.15", "DE", service="vpn"),
        ],
        {"100401"},
    ),
    Scenario(
        "unusual-country",
        "Eve fails in her home country and then succeeds from Nigeria.",
        [
            login(0, "eve", "failure", "203.0.113.10", "DE"),
            login(2, "eve", "failure", "203.0.113.10", "DE"),
            login(6, "eve", "success", "203.0.113.10", "NG"),
        ],
        {"100501"},
    ),
    Scenario(
        "eicar-executed",
        "A process starts the EICAR test file.",
        [file_event(0, "bob", "execute", "temp/sample.com")],
        {"100601"},
    ),
    Scenario(
        "eicar-written",
        "The EICAR test file is written to disk.",
        [file_event(0, "bob", "create", "temp/sample.com")],
        {"100701"},
    ),
    Scenario(
        "eicar-persistence",
        "The EICAR test file is copied into a Startup folder.",
        [file_event(0, "bob", "persist", "startup/update.com")],
        {"100801"},
    ),
]


def syslog_line(event):
    sha = event.sha256 or "-"
    path = event.path or "-"
    stamp = event.ts.strftime("%b %d %H:%M:%S")
    return (
        f"{stamp} lab-host dfir-lab: action={event.action} result={event.result} "
        f"user={event.user} srcip={event.srcip} country={event.country} "
        f"service={event.service} sha256={sha} path={path}"
    )
