"""Correlation rules for the lab use cases.

Wazuh is the runtime detector. These functions are the same decisions, so the
use cases can be checked without a manager. The rule IDs match
wazuh/rules/dfir-lab-rules.xml.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

# SHA-256 of the standard 68-byte EICAR antivirus test file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

LOGIN_SERVICES = {"ssh", "rdp", "windows"}
BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_FAILURES = 5
SPLIT_IP_FAILURES = 3
VPN_WINDOW = timedelta(minutes=10)
COUNTRY_WINDOW = timedelta(minutes=10)
TRAVEL_WINDOW = timedelta(hours=1)
SPEED_LIMIT_KMH = 800


@dataclass(frozen=True)
class LabEvent:
    ts: datetime
    action: str
    result: str
    user: str
    srcip: str
    country: str
    service: str
    sha256: str = ""
    path: str = ""


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    level: int
    user: str
    indicators: dict = field(default_factory=dict)
    summary: str = ""


def evaluate(events, homes):
    ordered = sorted(events, key=lambda event: event.ts)
    found = []
    for index, event in enumerate(ordered):
        found.extend(_match(event, ordered[:index], homes))
    return found


def _match(event, previous, homes):
    if event.action == "file" and event.sha256 == EICAR_SHA256:
        return _eicar(event)
    if event.action == "login" and event.result == "success":
        return _login_success(event, previous, homes)
    return []


def _eicar(event):
    kind = {
        "execute": ("100601", 12, "Suspicious file executed: EICAR test file"),
        "create": ("100701", 10, "EICAR test file written to disk"),
        "persist": ("100801", 13, "EICAR test file staged in a persistence location"),
    }.get(event.result)
    if kind is None:
        return []
    rule_id, level, title = kind
    return [Detection(
        rule_id, title, level, event.user,
        {"sha256": event.sha256, "path": event.path, "srcip": event.srcip, "service": event.service},
        f"{event.user} {event.result} {event.path}",
    )]


def _login_success(event, previous, homes):
    found = []
    if event.service in LOGIN_SERVICES:
        found.extend(_account_login(event, previous, homes))
    if event.service == "vpn":
        found.extend(_vpn(event, previous))
    return found


def _account_login(event, previous, homes):
    found = []
    successes = [
        item for item in previous
        if item.action == "login" and item.result == "success"
        and item.user == event.user and item.service in LOGIN_SERVICES
        and event.ts - item.ts <= TRAVEL_WINDOW and item.country != event.country
    ]
    if successes:
        prior = max(successes, key=lambda item: item.ts)
        from dfir_soc.geo import travel_speed_kmh
        speed = travel_speed_kmh(prior.country, event.country, (event.ts - prior.ts).total_seconds())
        if speed > SPEED_LIMIT_KMH:
            found.append(Detection(
                "100101",
                "Impossible travel login detected",
                12,
                event.user,
                {
                    "srcip": event.srcip,
                    "country": event.country,
                    "prior_srcip": prior.srcip,
                    "prior_country": prior.country,
                    "speed_kmh": round(speed),
                    "service": event.service,
                },
                f"{event.user} signed in from {prior.country} and then {event.country} at about {round(speed)} km/h",
            ))

    failures = _failures(previous, event, LOGIN_SERVICES, BRUTE_WINDOW)
    if len(failures) >= BRUTE_FAILURES:
        found.append(Detection(
            "100202",
            "Multiple login failures followed by a success",
            12,
            event.user,
            {"srcip": event.srcip, "country": event.country, "failures": len(failures), "service": event.service},
            f"{len(failures)} failures for {event.user} were followed by a successful login",
        ))
    failure_ips = {item.srcip for item in failures}
    if len(failures) >= SPLIT_IP_FAILURES and failure_ips and event.srcip not in failure_ips and len(failure_ips) == 1:
        found.append(Detection(
            "100301",
            "Failures from one IP followed by success from another",
            12,
            event.user,
            {
                "srcip": event.srcip,
                "failure_srcip": next(iter(failure_ips)),
                "country": event.country,
                "failures": len(failures),
                "service": event.service,
            },
            f"{event.user} failed from {next(iter(failure_ips))} and then succeeded from {event.srcip}",
        ))

    country_failures = _failures(previous, event, LOGIN_SERVICES, COUNTRY_WINDOW)
    other_country = [item for item in country_failures if item.country != event.country]
    home = homes.get(event.user, set())
    if other_country and event.country not in home:
        found.append(Detection(
            "100501",
            "Failed login followed by success from an unusual country",
            12,
            event.user,
            {
                "srcip": event.srcip,
                "country": event.country,
                "prior_country": other_country[-1].country,
                "home_countries": sorted(home),
                "service": event.service,
            },
            f"{event.user} failed from {other_country[-1].country} and succeeded from {event.country}, which is outside {sorted(home)}",
        ))
    return found


def _vpn(event, previous):
    failures = _failures(previous, event, {"vpn"}, VPN_WINDOW)
    other_source = [item for item in failures if item.srcip != event.srcip]
    if not other_source:
        return []
    return [Detection(
        "100401",
        "Failed VPN login followed by success from a new source",
        12,
        event.user,
        {
            "srcip": event.srcip,
            "failure_srcip": other_source[-1].srcip,
            "country": event.country,
            "service": "vpn",
        },
        f"VPN failures for {event.user} from {other_source[-1].srcip} were followed by success from {event.srcip}",
    )]


def _failures(previous, event, services, window):
    return [
        item for item in previous
        if item.action == "login" and item.result == "failure"
        and item.user == event.user and item.service in services
        and event.ts - item.ts <= window
    ]
