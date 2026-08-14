def calculate_risk(data):

    warning_count = data.get("warning", 0)
    error_count = data.get("error", 0)
    critical_count = data.get("critical", 0)
    failed_login_count = data.get("failed_logins", 0)

    # Calculate security risk score
    score = (
        warning_count
        + (error_count * 2)
        + (critical_count * 5)
        + (failed_login_count * 2)
    )

    # Determine risk level
    if score >= 15:
        level = "HIGH"

    elif score >= 7:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "level": level,
        "score": score
    }