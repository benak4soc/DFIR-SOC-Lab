# 3. Methodology

The work followed five steps.

1. **Name the assets.** Accounts for interactive login (`ssh`, `rdp`, `windows`), the VPN service, and the host that reports file activity through Sysmon.
2. **Fix the detection rules before building the stack.** Each use case has one rule id, one time window, and one threshold. The same decisions are implemented in Wazuh XML and in `src/dfir_soc/detect.py`, so the rules can be checked without a running manager.
3. **Generate known stories.** `src/dfir_soc/scenarios.py` holds eight event sequences with fixed timestamps. A ninth check confirms that a trip from Germany to France over two hours does not count as impossible travel.
4. **Separate detection from response.** Wazuh decides that an alert exists. Shuffle calls `POST /v1/playbook`. The playbook queries MISP, then asks DFIR-IRIS to create a case and an alert. If those services are not configured, the playbook still returns the case text and sets `delivered` to false.
5. **Judge the result against the stories.** A story passes when the rule ids produced by the detector are exactly the ids expected for that story. The playbook check passes when an EICAR execution produces a case plan that includes the MISP comment and a recommended action.

Home countries used by rule 100501 are listed in `wazuh/lists/home-countries.csv`: Alice and Eve in Germany, Bob and Carol in the United States, Dave in Germany.

Thresholds:

| Check | Window | Condition |
|---|---|---|
| Impossible travel (100101) | 1 hour | Two successful countries, implied speed above 800 km/h |
| Failures then success (100202) | 5 minutes | At least 5 failures, then a success |
| Other source IP (100301) | 5 minutes | At least 3 failures from one IP, success from another IP |
| VPN new source (100401) | 10 minutes | VPN failure, then VPN success from a different address |
| Unusual country (100501) | 10 minutes | Failure, then success in a country outside the home list |
| EICAR execute, create, persist (100601, 100701, 100801) | none | SHA-256 equals the EICAR test hash and the result is `execute`, `create`, or `persist` |

Speed uses a haversine distance between representative coordinates for the two countries, divided by the elapsed time. Those coordinates are a lab stand-in for GeoIP, not a location of a person.
