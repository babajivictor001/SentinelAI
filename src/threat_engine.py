def calculate_risk(data):

    score = (
        data["warning"]
        + data["error"] * 2
        + data["critical"] * 5
    )

    if score >= 8:
        return "HIGH"

    elif score >= 4:
        return "MEDIUM"

    else:
        return "LOW"