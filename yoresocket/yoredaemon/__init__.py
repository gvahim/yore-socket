"""
This module provides the daemon for the RE/YO protocol.
You should use the yoresocket package and not this.
Authors: YochaiE, PelegD

Functions:

    run_daemon() -- run a daemon to provide the computer RE/YO support.
    suggest_address() -- returns YO Address that this machine can use.
"""

from functions import run_daemon, suggest_address

__all__ = ['run_daemon', 'suggest_address']
