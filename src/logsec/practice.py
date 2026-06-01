def count_requests(ips):
    result = {}
    for ip in ips:
        if ip in result:
            result[ip] += 1
        else:
            result[ip] = 1
    return result

reports = [
    {"ip": "1.2.3.4", "risk_level": "CRITICAL"},
    {"ip": "5.5.5.5", "risk_level": "LOW"},
    {"ip": "9.9.9.9", "risk_level": "HIGH"},
]
# Should return: [{"ip": "1.2.3.4", ...}, {"ip": "9.9.9.9", ...}]
def filter_high_risk(reports):
    result = []
    for report in reports:
        if report["risk_level"] == "HIGH" or report["risk_level"] == "CRITICAL":
            result.append(report)
    return result
