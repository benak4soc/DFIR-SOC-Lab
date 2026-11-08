"""Clients for DFIR-IRIS case management and MISP indicator lookup."""

import json
from urllib import error, request


class IrisClient:
    def __init__(self, base_url, api_key, customer_id=1, classification_id=1, severity_id=4):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.customer_id = customer_id
        self.classification_id = classification_id
        self.severity_id = severity_id

    def create_case(self, name, description, soc_id):
        return self._post("/api/v2/cases", {
            "case_name": name,
            "case_description": description,
            "case_customer": self.customer_id,
            "case_soc_id": soc_id,
            "classification_id": self.classification_id,
        })

    def create_alert(self, title, description, source_ref, context):
        return self._post("/api/v2/alerts", {
            "alert_title": title,
            "alert_description": description,
            "alert_severity_id": self.severity_id,
            "alert_customer_id": self.customer_id,
            "alert_classification_id": self.classification_id,
            "alert_source": "Wazuh",
            "alert_source_ref": source_ref,
            "alert_context": context,
            "alert_tags": "dfir-lab",
        })

    def _post(self, path, payload):
        body = json.dumps(payload).encode()
        call = request.Request(
            self.base_url + path,
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(call, timeout=20) as response:
                return json.loads(response.read().decode())
        except error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"IRIS {path} returned {exc.code}: {detail[:400]}") from exc


class MispClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def lookup(self, value):
        body = json.dumps({"returnFormat": "json", "value": value, "limit": 5}).encode()
        call = request.Request(
            self.base_url + "/attributes/restSearch",
            data=body,
            headers={
                "Authorization": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(call, timeout=20) as response:
                payload = json.loads(response.read().decode())
        except error.URLError as exc:
            return {"status": "unavailable", "value": value, "attributes": [], "error": str(exc.reason)}
        attributes = payload.get("response", {}).get("Attribute", [])
        return {
            "status": "hit" if attributes else "miss",
            "value": value,
            "attributes": [
                {
                    "category": item.get("category", ""),
                    "type": item.get("type", ""),
                    "comment": item.get("comment", ""),
                    "event_id": item.get("event_id", ""),
                }
                for item in attributes
            ],
        }
