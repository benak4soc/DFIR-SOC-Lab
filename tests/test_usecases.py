from datetime import timedelta
from pathlib import Path

from dfir_soc.detect import EICAR_SHA256, evaluate
from dfir_soc.playbook import handle_alert
from dfir_soc.scenarios import HOME_COUNTRIES, SCENARIOS, T0, login, syslog_line


def ids_for(events):
    return {item.rule_id for item in evaluate(events, HOME_COUNTRIES)}


def test_each_story_raises_its_rule():
    assert len(SCENARIOS) == 8
    for scenario in SCENARIOS:
        assert ids_for(scenario.events) == scenario.rule_ids, scenario.name


def test_nearby_countries_are_not_impossible_travel():
    events = [
        login(0, "alice", "success", "203.0.113.10", "DE"),
        login(120, "alice", "success", "203.0.113.20", "FR"),
    ]
    assert "100101" not in ids_for(events)


def test_unrelated_file_hash_is_ignored():
    event = login(0, "bob", "success", "203.0.113.40", "US")
    event = event.__class__(
        T0, "file", "execute", "bob", "10.0.0.20", "DE", "sysmon",
        sha256="a" * 64, path="temp/notes.txt",
    )
    assert ids_for([event]) == set()


def test_syslog_line_keeps_fields_wazuh_can_decode():
    line = syslog_line(SCENARIOS[0].events[0])
    assert "dfir-lab: action=login result=success user=alice" in line
    assert "sha256=-" in line


def test_playbook_plans_an_iris_case_and_records_the_misp_hit():
    scenario = next(item for item in SCENARIOS if item.name == "eicar-executed")
    detection = evaluate(scenario.events, HOME_COUNTRIES)[0]
    alert = {
        "rule": {"id": detection.rule_id, "level": detection.level, "description": detection.title},
        "data": {
            "srcuser": detection.user,
            "srcip": detection.indicators["srcip"],
            "dfir.sha256": EICAR_SHA256,
            "dfir.path": detection.indicators["path"],
        },
    }

    class Misp:
        def lookup(self, value):
            if value == EICAR_SHA256:
                return {"status": "hit", "value": value, "attributes": [{"comment": "EICAR antivirus test file", "category": "Payload delivery"}]}
            return {"status": "miss", "value": value, "attributes": []}

    plan = handle_alert(alert, iris=None, misp=Misp())
    assert plan["delivered"] is False
    assert plan["rule_id"] == "100601"
    assert "EICAR antivirus test file" in plan["description"]
    assert "Recommended action:" in plan["description"]
    assert plan["soc_id"] == "DFIR-100601-bob"


def test_success_outside_the_failure_window_does_not_correlate():
    events = [
        login(0, "bob", "failure", "203.0.113.40", "US"),
        login(1, "bob", "failure", "203.0.113.40", "US"),
        login(2, "bob", "failure", "203.0.113.40", "US"),
        login(3, "bob", "failure", "203.0.113.40", "US"),
        login(4, "bob", "failure", "203.0.113.40", "US"),
        login(5, "bob", "failure", "203.0.113.40", "US"),
    ]
    late = events[-1].__class__(
        T0 + timedelta(minutes=30), "login", "success", "bob", "203.0.113.40", "US", "ssh",
    )
    assert "100202" not in ids_for(events + [late])


def test_wazuh_rules_use_the_same_ids():
    rules = Path(__file__).parents[1] / "wazuh" / "rules" / "dfir-lab-rules.xml"
    text = rules.read_text(encoding="utf-8")
    for scenario in SCENARIOS:
        for rule_id in scenario.rule_ids:
            assert f'id="{rule_id}"' in text
