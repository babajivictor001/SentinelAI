from src.utils import extract_ip


def analyze_logs(file):

    info_count = 0
    warning_count = 0
    error_count = 0
    critical_count = 0
    failed_login_count = 0

    suspicious_ips = set()
    login_attempts = {}

    total_events = 0

    # Store original log lines for the detection engine
    log_lines = []

    for line in file:

        line = line.strip()

        if not line:
            continue

        # Preserve the line for threat detection
        log_lines.append(line)

        total_events += 1

        if "INFO" in line:
            info_count += 1

        if "WARNING" in line:
            warning_count += 1

        if "ERROR" in line:
            error_count += 1

        if "CRITICAL" in line:
            critical_count += 1

        if "Failed login" in line:

            failed_login_count += 1

            ip = extract_ip(line)

            if ip:

                suspicious_ips.add(ip)

                if ip in login_attempts:
                    login_attempts[ip] += 1
                else:
                    login_attempts[ip] = 1

        if "Multiple failed login attempts" in line:

            ip = extract_ip(line)

            if ip:

                suspicious_ips.add(ip)

                if ip in login_attempts:
                    login_attempts[ip] += 2
                else:
                    login_attempts[ip] = 2

    return {

        "total_events": total_events,

        "info": info_count,

        "warning": warning_count,

        "error": error_count,

        "critical": critical_count,

        "failed_logins": failed_login_count,

        "suspicious_ips": list(suspicious_ips),

        "login_attempts": login_attempts,

        # Raw lines used by the detection engine
        "lines": log_lines
    }