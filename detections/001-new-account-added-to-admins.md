# Detection 001: New Local Account Added to Administrators

- Data source: wineventlog:security
- Event IDs: 4720 (account created), 4732 (member added to local group)
- MITRE ATT&CK: T1136.001 Create Account: Local Account, T1098 Account Manipulation
- Logic: the same account is created, then added to Administrators within 10 minutes on the same host
- Severity: High
- Result on BOTSv3: 1 match, FYODOR-L\svcvnc, created 06:08:17, added to Administrators at 06:08:35 (18 seconds)

## SPL

```spl
index=botsv3 sourcetype="wineventlog:security" (EventCode=4720 OR (EventCode=4732 Group_Name="Administrators"))
| rex field=Message "(?s)(?:New Account:|Member:)\s*Security ID:\s*(?<target_sid>\S+)"
| stats earliest(_time) as first_seen latest(_time) as last_seen values(EventCode) as codes values(Group_Name) as groups by host target_sid
| where mvfind(codes,"4720")>=0 AND mvfind(groups,"Administrators")>=0
| eval secs_to_admin=last_seen-first_seen
| where secs_to_admin<=600
| convert ctime(first_seen) ctime(last_seen)
```

## False positives

- IT staff creating admin accounts during provisioning
- Imaging and deployment tools

## Tuning

- Allowlist known admin actors and provisioning hosts
- Adjust the 600-second window

## Triage

1. Who performed the action (Subject account)?
2. Was a change ticket approved?
3. Check 4688 and Sysmon for the process that created the account
4. Check later logons by the new account (4624) and remote tools
