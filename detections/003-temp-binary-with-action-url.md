\# Detection 003: Binary in Temp Using a URL That Ends in .action



\- Data source: Sysmon (XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (process creation)

\- MITRE ATT\&CK: T1036.005 Masquerading: Match Legitimate Name or Location, T1059.004 Unix Shell

\- Logic: a process started from a Temp folder has a command line containing an http or https URL ending in .action, a pattern typical of Java web application endpoints

\- Severity: Medium to High

\- Result on BOTSv3: 1 image, C:\\Windows\\Temp\\unziped\\lsof-master\\iexeplorer.exe on FYODOR-L, 34 events between 07:05:40 and 07:34:01 (about 17 executions; each one produces a parent and a child record)



\## SPL



```spl

index=botsv3 earliest=0 sourcetype="\*sysmon\*" "<EventID>1</EventID>" "action"

| rex field=\_raw "Name='Image'>(?<img>\[^<]+)<"

| rex field=\_raw "Name='CommandLine'>(?<cmd>\[^<]+)<"

| where match(img,"(?i)\\\\\\\\temp\\\\\\\\") AND match(cmd,"(?i)https?://\\S+\\.action")

| stats count min(\_time) as first max(\_time) as last values(host) as host by img

| convert ctime(first) ctime(last)

```



The search uses stats so the long command lines (which can carry encoded payloads and credentials) are not displayed.



\## False positives



\- Installers or scripts in Temp that call an internal web application ending in .action

\- Developers testing a local application



\## Tuning



\- Allowlist known images and destination hosts

\- Extend the path check to other user-writable folders (AppData, Downloads, ProgramData)

\- Add the destination host as a field and alert on internal servers reached from workstations



\## Triage



1\. Compute and look up the SHA256 of the binary; check the file creation event (Sysmon EventID 11) and its parent

2\. Read the full command lines and the commands sent to the destination server

3\. Review the destination host logs (web access logs, osquery process events, auth.log)

4\. Check for reverse shell activity and new accounts on the destination (see Detection 002 and the INC-001 report)

