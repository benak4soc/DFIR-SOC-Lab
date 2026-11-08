# 6. Results

The test run on 6 November 2026 reported **7 passed**. Each of the eight stories produced only its expected rule. The playbook built an undelivered case plan for an EICAR execution, included the MISP comment "EICAR antivirus test file", and set the case id to `DFIR-100601-bob`. `delivered` was false because IRIS was not configured for that run. That is the intended offline result.

| Story | Input, in short | Rule observed |
|---|---|---|
| Impossible travel | Alice succeeds in DE, then 30 minutes later in BR | 100101 |
| Failures then success | Bob, 6 failures, then a success from the same address | 100202 |
| Other source IP | Carol, 3 failures from one address, success from another | 100301 |
| VPN new source | Dave, VPN failures, then success from a new address | 100401 |
| Unusual country | Eve fails in DE, then succeeds in NG, which is outside her home list | 100501 |
| EICAR executed | Hash matches, result `execute`, path `temp/sample.com` | 100601 |
| EICAR written | Hash matches, result `create` | 100701 |
| EICAR persistence | Hash matches, result `persist`, path `startup/update.com` | 100801 |

Two negative checks also held. A success in Germany followed two hours later by a success in France did not raise 100101, because the implied speed stays under 800 km/h. A file event with a different hash raised no rule. Six failures followed by a success 30 minutes later did not raise 100202, because that success is outside the 5-minute window.

These results show that the detection logic and the case text are consistent with the stories. They do not measure false positives on live authentication logs, and they do not show a round trip through a running Wazuh manager, Shuffle, MISP, and IRIS.
