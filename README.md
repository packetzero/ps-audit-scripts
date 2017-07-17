# ps-audit-scripts
Powershell scripts for setting local event log audit settings using auditpol.exe

Loads system-audit-settings.csv from local directory and if current local settings differ from desired settings, will set them accordingly, writing status to stdout.

# Example
The screenshot below is an example where a single setting doesn't match.
![sceenshot](misc/screenshot-audit-sync.png)

# References
[Event Log Cheatsheets](https://www.malwarearchaeology.com/cheat-sheets/)
