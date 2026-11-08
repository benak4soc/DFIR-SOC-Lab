# Account and endpoint detection lab with Wazuh, Shuffle, MISP, and DFIR-IRIS

Course project report. 6 November 2026.

The report is split into the sections below. Detection content, the playbook, and the enrichment event stay in their own folders.

| Section | Document |
|---|---|
| Introduction | [docs/01-introduction.md](docs/01-introduction.md) |
| Problem statement | [docs/02-problem-statement.md](docs/02-problem-statement.md) |
| Methodology | [docs/03-methodology.md](docs/03-methodology.md) |
| Architecture | [docs/04-architecture.md](docs/04-architecture.md) |
| Implementation | [docs/05-implementation.md](docs/05-implementation.md) |
| Results | [docs/06-results.md](docs/06-results.md) |
| Conclusion | [docs/07-conclusion.md](docs/07-conclusion.md) |

| Lab section | Path |
|---|---|
| Wazuh detection | `wazuh/` |
| Shuffle playbook | `src/dfir_soc/playbook.py`, `src/dfir_soc/webhook.py`, `compose.yaml` |
| MISP enrichment | `misp/`, `src/dfir_soc/clients.py` |
| DFIR-IRIS cases | `src/dfir_soc/clients.py`, `src/dfir_soc/playbook.py` |
| Stories and checks | `lab/`, `tests/` |
