BLOCKED_PATHS = ["/etc/passwd", "/etc/shadow"]


def is_blocked(path):
    return path in BLOCKED_PATHS
