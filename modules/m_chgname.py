"""
/chgname command
"""

import ircd


class Chghost(ircd.Command):
    """
    Changes a users' real nane (GECOS).
    Syntax: CHGNAME <user> <new real name>
    """

    def __init__(self):
        self.command = 'chgname'
        self.req_modes = 'o'
        self.params = 2

    def execute(self, client, recv):
        if type(client).__name__ == 'Server':
            source = client
            client = list(filter(lambda u: u.uid == recv[0][1:] or u.nickname == recv[0][1:], self.ircd.users))
            if not client:
                return
            client = client[0]
            recv = recv[1:]
        else:
            source = self.ircd

        target = list(filter(lambda u: u.nickname == recv[1], self.ircd.users))
        if not target:
            return client.sendraw(self.ERR.NOSUCHNICK, '{} :No such nick'.format(recv[1]))
        target = target[0]
        gecos = ' '.join(recv[2:])[:48]
        if gecos == target.realname or not gecos:
            return
        target.setinfo(gecos, t='gecos', source=source)
        self.ircd.snotice('s', '*** {} ({}@{}) used CHGNAME to change the GECOS of {} to "{}"'.format(client.nickname, client.ident, client.hostname, target.nickname, target.realname))
