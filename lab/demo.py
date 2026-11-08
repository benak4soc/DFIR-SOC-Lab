"""Run the eight stories and print the case Shuffle would open."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_soc.detect import evaluate
from dfir_soc.playbook import handle_alert
from dfir_soc.scenarios import HOME_COUNTRIES, SCENARIOS, syslog_line


class RecordingMisp:
    def lookup(self, value):
        if value == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
            return {
                "status": "hit",
                "value": value,
                "attributes": [{"category": "Payload delivery", "type": "sha256", "comment": "EICAR antivirus test file", "event_id": "1"}],
            }
        return {"status": "miss", "value": value, "attributes": []}


def main():
    misp = RecordingMisp()
    for scenario in SCENARIOS:
        detections = evaluate(scenario.events, HOME_COUNTRIES)
        print(f"\n{scenario.name}")
        print(scenario.summary)
        for event in scenario.events:
            print("  " + syslog_line(event))
        for detection in detections:
            alert = {
                "rule": {"id": detection.rule_id, "level": detection.level, "description": detection.title},
                "data": {"srcuser": detection.user, **_flat(detection.indicators)},
            }
            plan = handle_alert(alert, iris=None, misp=misp)
            print(f"  rule {detection.rule_id}: {plan['title']}")
            print(f"  case: {plan['soc_id']} delivered={plan['delivered']}")
    return 0


def _flat(indicators):
    data = {}
    if indicators.get("srcip"):
        data["srcip"] = indicators["srcip"]
    if indicators.get("country"):
        data["dfir.country"] = indicators["country"]
    if indicators.get("sha256"):
        data["dfir.sha256"] = indicators["sha256"]
    if indicators.get("path"):
        data["dfir.path"] = indicators["path"]
    return data


if __name__ == "__main__":
    sys.exit(main())
