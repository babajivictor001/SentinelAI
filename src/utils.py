def extract_ip(line):
    """
    Extract the last word in a log line.
    Usually this is the IP address.
    """
    parts = line.split()
    return parts[-1]


def separator():
    print("=" * 45)