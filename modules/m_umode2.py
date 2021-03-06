"""
/umode2 command (server)
"""

import ircd

from handle.functions import logging


class Umode2(ircd.Command):
    def __init__(self):
        self.command = 'umode2'
        self.req_class = 'Server'

    def execute(self, client, recv):
        # :asdf UMODE2 +ot
        target = next((u for u in self.ircd.users if u.uid == recv[0][1:] or u.nickname == recv[0][1:]), None)
        if not target:
            logging.info(f'Could not set umode for {recv[0][1:]}: maybe it got SVSKILLed?')
            return
        modeset = None
        for m in recv[2]:
            if m in '+-':
                modeset = m
                continue
            if modeset == '+':
                if m not in target.modes:
                    target.modes += m

            elif modeset == '-':
                target.modes = target.modes.replace(m, '')
                if m == 'o':
                    target.operflags = []
                    target.swhois = []
                    target.opermodes = ''
                elif m == 's':
                    target.snomasks = ''

        self.ircd.new_sync(client, ' '.join(recv))
