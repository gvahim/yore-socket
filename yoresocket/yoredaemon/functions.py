import socket


def suggest_address():
    """
    This function creates YO Address base on pc address (from A.B.C.D to C.D)
    """
    return '.'.join(socket.gethostbyname(socket.gethostname()).split('.')[2:])


def run_daemon(address, verbose_level=4, daemon_port=None, filter_addresses=None, send_error_port_not_open=True):
    """
    The function that boots everything up with YO address
    that we would like to register for this ProtocolDaemon.
    This is a blocking function


    Please note: Since there's no complicated network entities (router, DHCP server, etc.)
    we may statically select non-colliding addresses.

    :param address: YO Address 'A.B'
    :param verbose_level: how much noise to print (1 - all, 10 - almost nothing)
    :param daemon_port: The daemon localhost TCP Port. Use only if you use multiple YORE Daemons on the same
    computer (if you want to have multiple YO addresses on the same computer).
    :param addresses: Set a daemon filter for addresses to get packets from:
    None - for no filter, 'X.Y' for single address or list of addresses
    :param send_error_port_not_open: Allow daemon to send this error message.
    :return: socket object
    :return: return True when finished or False if can't register address
    """
    # import inside function to avoid import scapy (with is VERY heavy every time)
    from protocoldaemon import ProtocolDaemon

    print "Starting up YORE ProtocolDaemon"
    # Create a new Resocket ProtocolDaemon.
    d = ProtocolDaemon(daemon_port=daemon_port)
    d.set_verbose_level(verbose_level)
    if filter_addresses is not None:
        d.set_filter_address(filter_addresses)
    d.send_error_port_not_open = send_error_port_not_open
    # Try to register the ProtocolDaemon with the given YO address. If it succeeds,
    # run the ProtocolDaemon.
    if not d.register(address):
        return False
    d.run()
    return True
