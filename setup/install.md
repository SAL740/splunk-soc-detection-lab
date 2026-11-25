# Setup Notes

- Installed Splunk Enterprise 10.6.2.5 on Windows
- Downloaded the BOTS v3 dataset (319.7 MB) from the official S3 link
- Verified MD5: d7ccca99a01cff070dff3c139cdc10eb (matches the official value)
- Extracted to C:\Program Files\Splunk\etc\apps\botsv3_data_set
- Restarted Splunk
- Verified: index=botsv3 returns 1,944,092 events across 107 sourcetypes
- wineventlog:security has 46,469 events across 61 EventCodes
