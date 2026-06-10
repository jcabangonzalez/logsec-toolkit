# SIEM Queries — access.log Threat Findings

Generated from analysis of `samples/access.log` (2026-02-12 → 2026-05-19).

---

## Splunk SPL

### Threat 1 — Wordlist / Sensitive Path Scan
```spl
index=web
| search (uri="/.env" OR uri="/.git" OR uri="/phpmyadmin" OR uri="/wp-admin" OR uri="/admin")
| bin _time span=10s
| stats count as SensitiveHits dc(uri) as UniquePaths by src_ip, _time
| where SensitiveHits >= 3
| sort -SensitiveHits
| table _time, src_ip, SensitiveHits, UniquePaths
```

### Threat 2 — HTTP Flood Detection
```spl
index=web
| bin _time span=10s
| stats count as ReqCount by src_ip, uri, _time
| where ReqCount >= 10
| sort -ReqCount
| table _time, src_ip, uri, ReqCount
```

### Threat 3 — Brute Force then Recon (Correlated)
```spl
index=web status=401
| bin _time span=5m
| stats count as FailedLogins by src_ip, _time
| where FailedLogins >= 5
| join src_ip [
    search index=web (uri="/.env" OR uri="/.git" OR uri="/wp-admin" OR uri="/admin")
    | stats count as ReconHits, values(uri) as ReconPaths by src_ip
]
| eval AttackHour=strftime(_time, "%H")
| eval OffHours=if(AttackHour<"06" OR AttackHour>"22", "YES", "NO")
| table _time, src_ip, FailedLogins, ReconPaths, OffHours
```

### Threat 4 — sqlmap / SQL Injection via User-Agent
```spl
index=web
| search (useragent="*sqlmap*"
    OR uri_query="*UNION+SELECT*" OR uri_query="*UNION SELECT*"
    OR uri_query="*AND+1=1*" OR uri_query="*AND 1=1*"
    OR uri_query="*'+OR+'*" OR uri_query="*'--*"
    OR uri_query="*SLEEP(*" OR uri_query="*BENCHMARK(*")
| eval Severity=if(status=500, "CRITICAL - Server Error on SQLi", "HIGH - SQLi Probe")
| stats count as Payloads, values(uri_query) as Queries, values(status) as StatusCodes by src_ip, Severity
| sort -Payloads
| table src_ip, Severity, Payloads, StatusCodes, Queries
```

### Threat 5 — Internal Host SQL Injection
```spl
index=web
| where match(src_ip, "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)")
| search (uri_query="*'+OR+'*" OR uri_query="*%27%20OR*"
    OR uri_query="*UNION SELECT*" OR uri_query="*AND 1=1*")
| stats count as Attempts, values(uri_query) as Payloads, values(status) as Responses by src_ip
| table src_ip, Attempts, Payloads, Responses
```

---

## Elastic KQL (Kibana Discover)

### Threat 1 — Sensitive Path Scanning
```kql
url.path: ("/.env" OR "/.git" OR "/phpmyadmin" OR "/wp-admin" OR "/admin")
AND NOT source.ip: ("127.0.0.1" OR "::1")
```

### Threat 2 — HTTP Flood
```kql
http.response.status_code: 200
AND http.request.method: "GET"
```
> Then add a **Lens** visualization: count by `source.ip` over 10s intervals, filter `count >= 10`.

### Threat 3 — Brute Force + Off-Hours
```kql
http.response.status_code: 401
AND url.path: "/login"
AND NOT @timestamp: [now/d+6h TO now/d+22h]
```

### Threat 4 — SQL Injection (sqlmap + payloads)
```kql
user_agent.original: *sqlmap*
OR url.query: (*UNION+SELECT* OR *AND+1=1* OR *'+OR+'* OR *SLEEP(* OR *BENCHMARK(*)
```

### Threat 5 — Internal SQLi
```kql
source.ip: 192.168.0.0/16
AND url.query: (*'+OR+'* OR *%27%20OR* OR *UNION+SELECT*)
```

---

## Elastic EQL — Sequence Rules

### Brute Force → Recon Sequence
```eql
sequence by source.ip with maxspan=10m
  [http where http.response.status_code == 401
   | where count() >= 5]
  [http where url.path in ("/.env", "/.git", "/wp-admin", "/phpmyadmin", "/admin")]
```

### sqlmap Escalation — Probe to Server Error
```eql
sequence by source.ip with maxspan=60s
  [http where user_agent.original like "*sqlmap*"
   and http.response.status_code == 200]
  [http where user_agent.original like "*sqlmap*"
   and http.response.status_code == 500]
```

---

## Microsoft Sentinel KQL

### Threat 3 — Off-Hours Brute Force
```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where RequestURL contains "/login" and RequestContext contains "401"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour between (0 .. 6)
| summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

### Threat 4 — SQLi with Server Error
```kql
W3CIISLog
| where TimeGenerated > ago(7d)
| where csUriQuery contains "UNION" or csUriQuery contains "SELECT"
    or csUriQuery contains "AND+1=1" or csUriQuery contains "'+OR+'"
    or csUserAgent contains "sqlmap"
| extend IsServerError = iff(scStatus == 500, true, false)
| summarize Attempts = count(), ServerErrors = countif(IsServerError)
    by cIP, csUriStem, csUserAgent
| extend RiskLevel = iff(ServerErrors > 0, "CRITICAL", "HIGH")
| order by ServerErrors desc
```

### Threat 5 — Internal Host SQLi
```kql
W3CIISLog
| where TimeGenerated > ago(7d)
| where cIP matches regex @"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
| where csUriQuery contains "OR '1'='1" or csUriQuery contains "%27%20OR"
    or csUriQuery contains "UNION SELECT"
| project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus, scBytes
| order by TimeGenerated desc
```
