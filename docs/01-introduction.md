# 1. Introduction

A small security operations lab was built to detect suspicious sign-ins and a known antivirus test file, then turn each detection into a case an analyst can report. The protected things are user accounts, VPN access, and the workstation. The lab does not defend one business application. It watches whether a login should be trusted, and whether a file was written, executed, or left in a startup location.

Four open-source systems divide the work.

| System | Role |
|---|---|
| Wazuh | Collects logs from the reporting devices and raises the alert |
| Shuffle | Receives the alert and runs the response workflow |
| MISP | Says whether the IP address or file hash is already known |
| DFIR-IRIS | Stores the case, the alert, and the material for the DFIR report |

The reporting devices are the systems that emit the original events. In this lab they are a workstation, represented by a Wazuh agent and Sysmon, and a VPN gateway. Wazuh is the first place an analyst sees the alert. DFIR-IRIS is where the case is written up. Shuffle only carries the alert from one system to the next.

Eight use cases were defined. Five concern authentication. Three use the SHA-256 of the standard EICAR antivirus test file, `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`. The test file itself is not stored in the project.
