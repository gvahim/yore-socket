"""
This module provides socket operations and some related functions for the 
RE/YO protocol.

Authors: YochaiE, PelegD

Functions:

    run_daemon() -- run a daemon to provide the computer RE/YO support
    suggest_address() -- returns YO Address that this machine can use
    yoresocket() -- create a new socket object. You should run run_daemon() 
                    functions before in another process.

Integer constants:

    SOCK_RAW, SOCK_RE -- socket types

Special objects:

    YOREException -- general exception that can be raise
    YOREUnsupportedProtocolAction -- exception raised by illegal use of the api 
                                     (You did something wrong)
    YOREDaemonToAPICommunicationError -- exception raised by the communication 
                                         with the daemon (it's probably down)
    YOREDaemonToAPIValueError -- exception raised by the communication with the 
                                 daemon (Probably stack bug)
    YOREProtocolError -- exception raised by illegal use of YO/RE protocol

"""

from YOREException import (YOREException, YOREDaemonToAPIValueError,
                           YOREUnsupportedProtocolAction,
                           YOREDaemonToAPICommunicationError, YOREProtocolError,
                           YORETimeoutException)
from constants import SOCK_RAW, SOCK_RE, BLOCKING, NON_BLOCKING
from functions import yoresocket
from yoredaemon import run_daemon, suggest_address

__all__ = ['YOREException', 'YOREDaemonToAPIValueError',
           'YOREUnsupportedProtocolAction', 'YOREProtocolError',
           'YOREDaemonToAPICommunicationError', 'YORETimeoutException',
           'yoresocket', 'SOCK_RAW', 'SOCK_RE',
           'run_daemon', 'suggest_address', 'BLOCKING', 'NON_BLOCKING']
