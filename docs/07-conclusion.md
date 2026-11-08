# 7. Conclusion

The lab protects accounts, VPN access, and the workstation by alerting on sequences rather than on single lines. The workstation agent and the VPN gateway are the reporting devices. Wazuh is the detection report. DFIR-IRIS is the case report an analyst can turn into a DFIR write-up: rule id, user, addresses, countries, hash, MISP result, recommended action, and the decision the analyst actually took.

The eight stories behave as specified under automated checks. The next evidence to collect is a `wazuh-logtest` pass for each line, one live case in IRIS for each rule id, and one exported report per case. Until that run exists, the project demonstrates the method and the rules, not a deployed operations center.
