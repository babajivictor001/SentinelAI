from src.utils import separator


def generate_report(data, risk):

    separator()
    print("      SENTINELAI SECURITY REPORT")
    separator()

    print("INFO Events           :", data["info"])
    print("WARNING Events        :", data["warning"])
    print("ERROR Events          :", data["error"])
    print("CRITICAL Events       :", data["critical"])
    print("Failed Logins         :", data["failed"])

    total = (
        data["info"]
        + data["warning"]
        + data["error"]
        + data["critical"]
    )

    print()
    print("Total Events :", total)

    print()
    print("Suspicious IPs")

    for ip in data["ips"]:
        print("-", ip)

    print()
    print("Threat Level :", risk)

    separator()

    print("\nLogin Attempts")

    for ip, count in data["attempts"].items():
        print(ip, "->", count)