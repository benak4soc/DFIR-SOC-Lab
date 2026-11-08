# DFIR SOC lab

Wazuh detects the cases below. Shuffle receives those alerts and runs the playbook. The playbook asks MISP about the IP or file hash, then opens a case and an alert in DFIR-IRIS. The playbook does not disable accounts or isolate hosts. It records a recommended action for an analyst.

## Report

| Section | Document |
|---|---|
| Introduction | [docs/01-introduction.md](docs/01-introduction.md) |
| Problem statement | [docs/02-problem-statement.md](docs/02-problem-statement.md) |
| Methodology | [docs/03-methodology.md](docs/03-methodology.md) |
| Architecture | [docs/04-architecture.md](docs/04-architecture.md) |
| Implementation | [docs/05-implementation.md](docs/05-implementation.md) |
| Results | [docs/06-results.md](docs/06-results.md) |
| Conclusion | [docs/07-conclusion.md](docs/07-conclusion.md) |

The index of those sections is [PROJECT.md](PROJECT.md).

## Repository sections

| Section | Path |
|---|---|
| Wazuh detection | `wazuh/` |
| Shuffle orchestration | `src/dfir_soc/playbook.py`, `src/dfir_soc/webhook.py` |
| MISP enrichment | `misp/` |
| DFIR-IRIS cases | `src/dfir_soc/clients.py` |
| Lab stories | `lab/` |
| Checks | `tests/` |

The login stories are synthetic `dfir-lab:` log lines. The file stories use the SHA-256 of the standard EICAR antivirus test file (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`). The project does not store the EICAR file itself.

## Use cases

| Rule | What Wazuh reports |
|---|---|
| 100101 | Impossible travel: the same user succeeds from two countries within an hour, faster than 800 km/h |
| 100202 | Five or more failures for one account, then a success |
| 100301 | Failures from one IP, then a success from a different IP |
| 100401 | Failed VPN login, then a success from a new source |
| 100501 | Failed login, then a success from a country outside that user's home list |
| 100601 | EICAR test file executed |
| 100701 | EICAR test file written to disk |
| 100801 | EICAR test file copied to a persistence location such as Startup |

Home countries are in `wazuh/lists/home-countries.csv`.

## Check the detections

```bash
cd dfir-soc
python -m pip install -r requirements.txt
python -m pytest
python lab/demo.py
```

`lab/demo.py` prints the log lines and the IRIS case id each story would open.

## Playbook webhook

Shuffle posts the Wazuh alert JSON to `POST /v1/playbook`. Copy `.env.example` to `.env` and set the IRIS and MISP values when those services are up. Leave them empty to plan the case without sending it.

```bash
docker compose up
```

The webhook listens on `http://127.0.0.1:8088`. `GET /health` returns `{"status":"ok"}`.

## Wire the four platforms

These are the current stable installs. Together they want about 16 GB of RAM, so use a larger machine than a 4 GB laptop.

**Wazuh 4.14.10**

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.10
cd wazuh-docker/single-node
docker compose up -d
```

Dashboard: `https://localhost`. After the manager is healthy, copy the lab content in and restart the manager:

```bash
docker compose cp ../../dfir-soc/wazuh/decoders/dfir-lab-decoder.xml wazuh.manager:/var/ossec/etc/decoders/dfir-lab-decoder.xml
docker compose cp ../../dfir-soc/wazuh/rules/dfir-lab-rules.xml wazuh.manager:/var/ossec/etc/rules/dfir-lab-rules.xml
docker compose exec wazuh.manager chown wazuh:wazuh /var/ossec/etc/decoders/dfir-lab-decoder.xml /var/ossec/etc/rules/dfir-lab-rules.xml
```

Append `wazuh/integration/shuffle.xml` inside the manager's `/var/ossec/etc/ossec.conf`, with the real Shuffle webhook URL, then restart the manager. Send a lab line from `python lab/demo.py` to the manager log collector, or paste one line into `wazuh-logtest`.

**Shuffle**

```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
docker compose up -d
```

Create one workflow from scratch:

1. Webhook trigger. Start it and copy the webhook URL into the Wazuh integration.
2. HTTP app, POST `http://playbook:8088/v1/playbook` (or `http://<host>:8088/v1/playbook` if Shuffle is on another Docker network). Body is the webhook execution, header `X-Lab-Token` from `.env`.
3. Save and start the workflow.

That HTTP call is the orchestration step: MISP lookup, then IRIS case and alert.

**DFIR-IRIS v2.4.29**

```bash
git clone https://github.com/dfir-iris/iris-web.git -b v2.4.29
cd iris-web
# Follow the repository README to create certificates and the .env file.
docker compose up -d
```

Create an API key under **My settings**. Put it in `IRIS_API_KEY`. The playbook uses `POST /api/v2/cases` and `POST /api/v2/alerts`. If IRIS rejects the classification or severity id, set `IRIS_CLASSIFICATION_ID` and `IRIS_SEVERITY_ID` to values from that instance.

**MISP**

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
docker compose up -d
```

Create an automation key. Set `MISP_URL` and `MISP_API_KEY`. Add the event in `misp/eicar-event.json` so an EICAR hash comes back as "EICAR antivirus test file". The playbook searches `POST /attributes/restSearch`.

## Log shape

```text
dfir-lab: action=login result=failure user=alice srcip=203.0.113.10 country=DE service=ssh sha256=- path=-
dfir-lab: action=file result=execute user=bob srcip=10.0.0.20 country=DE service=sysmon sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f path=temp/sample.com
```

`service` is `ssh`, `rdp`, `windows`, `vpn`, or `sysmon`. File results are `execute`, `create`, or `persist`.
