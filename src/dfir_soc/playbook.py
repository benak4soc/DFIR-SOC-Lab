"""Turn a Wazuh alert into an IRIS case enriched from MISP.

Shuffle is the orchestrator. Its webhook receives the Wazuh alert and posts
that JSON here, or a Shuffle HTTP node performs the same two calls.
Nothing in this playbook isolates a host or changes an account.
"""

from dfir_soc.detect import EICAR_SHA256

RECOMMENDATIONS = {
    "100101": "Contact the user out of band. Revoke the newer session if they do not recognize the login.",
    "100202": "Reset the account password and review the successful session.",
    "100301": "Treat the successful source as untrusted until the user confirms it.",
    "100401": "Review the VPN profile and the new source address with the user.",
    "100501": "Confirm whether travel was expected. The success is outside the user's home countries.",
    "100601": "The hash is the EICAR antivirus test file. Record the host and remove the file if this was not an approved test.",
    "100701": "The hash is the EICAR antivirus test file. Record the path and remove the dropped copy if this was not an approved test.",
    "100801": "The hash is the EICAR antivirus test file staged for persistence. Record the path and remove it if this was not an approved test.",
}


def handle_alert(alert, iris, misp):
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id", ""))
    data = alert.get("data") or {}
    user = data.get("srcuser") or data.get("dstuser") or "unknown"
    indicators = _indicators(data)
    enrichment = []
    if misp is not None:
        for value in indicators["lookup"]:
            enrichment.append(misp.lookup(value))
    title = rule.get("description") or RECOMMENDATIONS.get(rule_id, "DFIR lab alert")
    recommendation = RECOMMENDATIONS.get(rule_id, "Review the alert and record the decision in the case.")
    description = _description(title, user, indicators, enrichment, recommendation)
    soc_id = f"DFIR-{rule_id}-{user}"
    plan = {
        "rule_id": rule_id,
        "title": title,
        "soc_id": soc_id,
        "user": user,
        "recommendation": recommendation,
        "enrichment": enrichment,
        "description": description,
    }
    if iris is None:
        plan["delivered"] = False
        return plan
    case = iris.create_case(title[:120], description, soc_id)
    iris_alert = iris.create_alert(title[:120], description, soc_id, {"wazuh": alert, "enrichment": enrichment})
    plan["delivered"] = True
    plan["iris_case"] = case
    plan["iris_alert"] = iris_alert
    return plan


def _indicators(data):
    values = []
    srcip = data.get("srcip") or ""
    sha256 = (data.get("dfir.sha256") or data.get("sha256") or "")
    if srcip:
        values.append(srcip)
    if sha256 and sha256 not in {"-", EICAR_SHA256}:
        values.append(sha256)
    if sha256 == EICAR_SHA256:
        values.append(sha256)
    return {
        "srcip": srcip,
        "country": data.get("dfir.country") or data.get("country") or "",
        "sha256": sha256,
        "path": data.get("dfir.path") or data.get("path") or "",
        "lookup": values,
    }


def _description(title, user, indicators, enrichment, recommendation):
    lines = [
        title,
        f"User: {user}",
        f"Source IP: {indicators['srcip'] or '-'}",
        f"Country: {indicators['country'] or '-'}",
        f"SHA-256: {indicators['sha256'] or '-'}",
        f"Path: {indicators['path'] or '-'}",
        "MISP:",
    ]
    if not enrichment:
        lines.append("- enrichment was not requested")
    for item in enrichment:
        if item.get("status") == "hit":
            comments = "; ".join(attr.get("comment") or attr.get("category") or "match" for attr in item["attributes"])
            lines.append(f"- {item['value']}: {comments}")
        elif item.get("status") == "unavailable":
            lines.append(f"- {item['value']}: MISP unavailable")
        else:
            lines.append(f"- {item['value']}: no matching attribute")
    lines.append(f"Recommended action: {recommendation}")
    return "\n".join(lines)
