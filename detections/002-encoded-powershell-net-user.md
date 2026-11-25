\# Detection 002: Encoded PowerShell Spawning net user /add



\- Data source: Sysmon (XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (process creation)

\- MITRE ATT\&CK: T1059.001 PowerShell, T1027 Obfuscated Files or Information, T1136.001 Create Account: Local Account, T1098 Account Manipulation

\- Logic: a powershell.exe parent started with an encoded command (-enc) launches net.exe that creates a local account or adds a member to the Administrators group

\- Severity: High

\- Result on BOTSv3: 2 matches on FYODOR-L, net.exe at 06:08:17 (net user /add svcvnc) and 06:08:35 (net localgroup administrators svcvnc /add)



\## SPL



```spl

index=botsv3 earliest=0 sourcetype="\*sysmon\*" "<EventID>1</EventID>"

| rex field=\_raw "Name='Image'>(?<img>\[^<]+)<"

| rex field=\_raw "Name='CommandLine'>(?<cmd>\[^<]+)<"

| rex field=\_raw "Name='ParentImage'>(?<parent\_img>\[^<]+)<"

| rex field=\_raw "Name='ParentCommandLine'>(?<parent\_cmd>\[^<]+)<"

| where like(lower(parent\_img),"%powershell.exe") AND like(lower(parent\_cmd),"% -enc%") AND (like(lower(cmd),"%net%user%/add%") OR like(lower(cmd),"%localgroup administrators%/add%"))

| eval cmd=replace(cmd,"(?i)(/add\\s+\\S+\\s+)\\S+","\\1\[REDACTED]")

| table \_time host img cmd parent\_img

```



Sysmon fields are not extracted in this lab, so the search uses rex on \_raw. The eval line hides the password that follows the account name in net user /add.



\## False positives



\- Management or deployment tools that run encoded PowerShell to create service or admin accounts

\- Administrators using encoded commands in provisioning scripts



\## Tuning



\- Allowlist known tools by parent command line and by host

\- Also cover other parents (cmd.exe, wscript.exe) and the net1.exe image

\- The pattern " -enc" covers -enc and -EncodedCommand; it does not cover the short form -e



\## Triage



1\. Decode the encoded command safely (do not run it) and read what it does

2\. Review the parent process chain and the user who ran it

3\. Check network connections (Sysmon EventID 3) from the parent PowerShell process

4\. Check Security events 4720 and 4732 for the same account (see Detection 001)

5\. Review later logons by the new account (4624)

