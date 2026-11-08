# 5. Implementation

| Path | Purpose |
|---|---|
| `wazuh/decoders/dfir-lab-decoder.xml` | Extracts action, result, user, source IP, country, service, hash, and path |
| `wazuh/rules/dfir-lab-rules.xml` | Parent events at level 3 and the eight correlation rules |
| `wazuh/integration/shuffle.xml` | Sends only those rule ids to Shuffle |
| `wazuh/lists/home-countries.csv` | Expected country for each lab user |
| `src/dfir_soc/detect.py` | The same decisions, runnable without the manager |
| `src/dfir_soc/geo.py` | Distance and speed for impossible travel |
| `src/dfir_soc/scenarios.py` | The eight stories and the syslog line format |
| `src/dfir_soc/playbook.py` | MISP enrichment text, recommendation, and IRIS payload |
| `src/dfir_soc/clients.py` | `POST /api/v2/cases`, `POST /api/v2/alerts`, and MISP `POST /attributes/restSearch` |
| `src/dfir_soc/webhook.py` | `GET /health` and `POST /v1/playbook` |
| `misp/eicar-event.json` | Local MISP event for the EICAR hash |
| `compose.yaml` | Starts the playbook webhook on `127.0.0.1:8088` |
| `tests/test_usecases.py` | Checks every story, one negative travel case, and the EICAR case plan |
| `lab/demo.py` | Prints each story, its log lines, and the case id that would be opened |

Wazuh 4.14.10, Shuffle, DFIR-IRIS v2.4.29, and MISP are installed from their public repositories when a machine has about 16 GB of RAM. No vendor account is required. API keys are created locally after the containers start. The checked run in this project used the Python detector and playbook, because that full platform was not started here.

A local check is:

```bash
python -m pip install -r requirements.txt
python -m pytest
python lab/demo.py
```

Platform install steps are in the repository [README](../README.md).
