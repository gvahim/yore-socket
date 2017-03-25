import resocket


def yoresocket(protocol, daemon_port=None):
    """
    Open a socket of the given type.
    A socket object represents one endpoint of a network connection.
    Must run a the daemon (in a different process) before using this.

    Thread safe notes - this object is  safe only in the non blocking mode.
    (in the blocking mode you may have to wait to other thread recv \ recvfrom response)

    :param protocol: yoresocket.SOCK_RE or yoresocket.SOCK_RAW.
    :param daemon_port: The daemon localhost TCP Port. Use only if you use multiple YORE Daemons on the same
    computer (if you want to have multiple YO addresses on the same computer).
    :return: socket object
    """
    return resocket.Resocket(protocol, daemon_port=daemon_port)
