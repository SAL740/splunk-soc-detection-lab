# \# Splunk SOC Detection Lab

# 

# A hands-on SOC lab built on Splunk Enterprise and the public Boss of the SOC v3 (BOTS v3) dataset. It covers one investigation, INC-001, and detection searches derived from it.

# 

# \## Environment

# 

# | Item | Value |

# |---|---|

# | Platform | Splunk Enterprise 10.6.2.5 on Windows |

# | Dataset | BOTS v3, index `botsv3` |

# | Size | 1,944,092 events, 107 sourcetypes |

# | Note | Sysmon fields are not extracted, so searches use `rex` on `\_raw` |

# 

# \## Repository contents

# 

# | Path | Contents |

# |---|---|

# | `investigations/INC-001-report.md` | Investigation report: timeline, findings, IOCs, MITRE mapping, detections |

# | `detections/` | Detection write-ups (001 so far; 002 and 003 are described in the report) |

# | `screenshots/` | Evidence of the data load and detection results |

# | `setup/install.md` | Setup steps (to be added) |

# 

# \## Investigation INC-001 in brief

# 

# A hidden, encoded PowerShell process on the Windows host FYODOR-L created an administrator account (`svcvnc`) and contacted an external address. A tool in `C:\\Windows\\Temp` then sent commands to a web application on the Linux host `hoth`, including a reverse shell attempt and the creation of a UID 0 account (`tomcat7`). Details, confidence labels and open questions are in the report.

# 

# \## Detections

# 

# | ID | Purpose | Status |

# |---|---|---|

# | 001 | Local account created and added to Administrators within 600 seconds | Validated |

# | 002 | Hidden encoded PowerShell parent spawning `net user /add` or `net localgroup administrators /add` | Validated |

# | 003 | Binary under `\\Temp\\` with a URL ending in `.action` in its command line | Validated |

# | 004 | High count of `powershell.exe` connections to one external address | Idea |

# | 005 | Linux `useradd` creating a UID 0 account | Draft |

# 

# Validation means each search returned the known malicious events in BOTS v3 and no unexpected hosts. It was tested on one incident only; the false-positive rate in a production environment is unknown.

# 

# \## Handling notes

# 

# \- Passwords found in command lines are replaced with `\[REDACTED]`.

# \- Encoded payloads and exploit text are not reproduced.

# \- BOTS v3 is a public training dataset; no real organisation's data is included.

