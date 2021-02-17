"""
/time command
"""

import ircd
from time import strftime


class Time(ircd.Command):
    """
    Displays server time.
    """

    def __init__(self):
        self.command = 'time'

    def execute(self, client, recv):
        info = strftime("%A %B %d %Y -- %H:%M:%S %z UTC")
        client.sendraw(self.RPL.TIME, info)
