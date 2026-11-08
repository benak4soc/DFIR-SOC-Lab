# 2. Problem statement

Account takeover and a dropped file are easy to miss when each log line is read alone. One failed password is normal. One successful login is normal. The useful signal is the sequence: many failures and then a success, a success from a second address, two countries in too little time, or a test file appearing in Startup.

The problem addressed here is how to:

1. Turn those sequences into a small set of alerts with stable rule identifiers.
2. Enrich each alert with threat-intelligence context.
3. Open one case per alert so an analyst can record a defensive decision.
4. Keep that case complete enough to write a DFIR report.

The lab also had to stay safe to demonstrate. Login stories are synthetic `dfir-lab:` lines. File stories match a published test hash. The playbook recommends an action. It does not reset a password, revoke a session, or remove a file by itself.
