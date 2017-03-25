class YOREException(Exception):
    """
    basic error handling options for RE/YO stack
    """
    pass


class YORETimeoutException(YOREException):
    """
    exception raised if recv of recv_from commands waited too much
    """
    pass


class YOREUnsupportedProtocolAction(YOREException):
    """
    exception raised by illegal use of the api (You did something wrong)
    """
    pass


class YOREDaemonToAPICommunicationError(YOREException):
    """
    exception raised by the communication with the daemon (the daemon is down)
    """
    pass


class YOREDaemonToAPIValueError(YOREException):
    """
    exception raised by the communication with the daemon (Probably stack bug)
    """
    pass


class YOREProtocolError(YOREException):
    """
    exception raised by illegal use of YO/RE protocol
    """
    pass
