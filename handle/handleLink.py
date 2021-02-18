import time
import threading
import socket
import hashlib
from ircd import Server
from handle.functions import IPtoBase64, logging, is_match

W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
R2 = '\033[91m'  # bright red
G = '\033[32m'  # green
G2 = '\033[92m'  # bright green
Y = '\033[33m'  # yellow
B = '\033[34m'  # blue
P = '\033[35m'  # purple


def syncChannels(ircd, newserver):
    for c in [c for c in ircd.channels if c.users and c.name[0] != '&']:
        modeparams = []
        for mode in c.modes:
            if mode in ircd.chan_params[c]:
                logging.debug(f"Preparing param mode {mode} for syncing: {ircd.chan_params[c][mode]}")
                modeparams.append(ircd.chan_params[c][mode])

        modeparams = ' {}'.format(' '.join(modeparams)) if modeparams else '{}'.format(' '.join(modeparams))
        memberlist, banlist, excepts, invex, prefix = [], [], [], [], ''
        for user in [user for user in c.users if '^' not in user.modes]:
            if 'q' in c.usermodes[user]:
                prefix += '*'
            if 'a' in c.usermodes[user]:
                prefix += '~'
            if 'o' in c.usermodes[user]:
                prefix += '@'
            if 'h' in c.usermodes[user]:
                prefix += '%'
            if 'v' in c.usermodes[user]:
                prefix += '+'
            member = '{}{}'.format(prefix, user.uid)
            prefix = ''
            memberlist.append(member)
        memberlist = ' '.join(memberlist)
        bans = ' '.join(['&' + x for x in [x for x in c.bans]]) + ' ' if list(c.bans) else ''
        exempts = ' '.join(['"' + x for x in [x for x in c.excepts]]) + ' ' if list(c.excepts) else ''
        invex = ' '.join(["'" + x for x in [x for x in c.invex]]) + ' ' if list(c.invex) else ''

        # List of mode classes of type 0.
        modes_with_list = [m for m in ircd.channel_mode_class if m.type == 0 if hasattr(c, m.list_name)]
        module_mode_lists = ''
        for m in modes_with_list:
            prefix = getattr(m, 'mode_prefix')
            m_list_name = getattr(m, 'list_name')  # whitelist
            for entry in getattr(c, m_list_name):
                module_mode_lists += prefix + entry + ' '

        module_mode_lists = module_mode_lists.strip()

        data = '{} {} +{}{} :{} {}{}{}{}'.format(c.creation, c.name, c.modes, modeparams, memberlist, bans, exempts, invex, module_mode_lists)
        newserver._send(':{} SJOIN {}'.format(ircd.sid, data))
        if c.topic:
            data = ':{} TOPIC {} {} {} :{}'.format(ircd.sid, c.name, c.topic_author, c.topic_time, c.topic)
            newserver._send(data)


def selfIntroduction(ircd, newserver, outgoing=False):
    try:
        if newserver not in ircd.introducedTo:
            if outgoing:
                destPass = ircd.conf['link'][newserver.hostname]['pass']
                newserver._send(':{} PASS :{}'.format(ircd.sid, destPass))
            info = []
            for row in ircd.server_support:
                value = ircd.support[row]
                info.append('{}{}'.format(row, '={}'.format(value) if value else ''))
            newserver._send(':{} PROTOCTL EAUTH={} SID={} {}'.format(ircd.sid, ircd.hostname, ircd.sid, ' '.join(info)))
            newserver._send(':{} PROTOCTL NOQUIT EAUTH SID NICKv2 CLK SJOIN SJOIN2 UMODE2 VL SJ3 TKLEXT TKLEXT2 NICKIP ESVID EXTSWHOIS'.format(ircd.sid))
            version = 'P{}-{}'.format(ircd.versionnumber.replace('.', ''), ircd.sid)
            local_modules = [m.__name__ for m in ircd.modules]
            modlist = []
            for entry in local_modules:
                totlen = len(' '.join(modlist))
                if totlen >= 400:
                    newserver._send('MODLIST :{}'.format(' '.join(modlist)))
                    modlist = []
                modlist.append(entry)
            if modlist:
                newserver._send('MODLIST :{}'.format(' '.join(modlist)))
            if outgoing:
                newserver._send(f':{ircd.sid} SID {ircd.hostname} 1 {ircd.sid} :{ircd.name}')
            else:
                newserver._send('SERVER {} 1 :{} {}'.format(ircd.hostname, version, ircd.name))
            logging.info('{}Introduced myself to {}. Expecting remote sync sequence...{}'.format(Y, newserver.hostname, W))
        ircd.introducedTo.append(newserver)

    except Exception as ex:
        logging.exception(ex)


def syncUsers(ircd, newserver, local_only):
    try:
        totalServers = [ircd]
        if not local_only:
            totalServers.extend(ircd.servers)
        for server in [server for server in totalServers if server != newserver and server.introducedBy != newserver and newserver.introducedBy != server and server not in newserver.syncDone and newserver.socket]:
            newserver.syncDone.append(server)
            logging.info('{}Syncing info from {} to {}{}'.format(Y, server.hostname, newserver.hostname, W))
            for u in [u for u in ircd.users if u.server == server and u.registered]:
                ip = IPtoBase64(u.ip) if u.ip.replace('.', '').isdigit() else u.ip
                if not ip:
                    ip = '*'
                hopcount = str(u.server.hopcount + 1)
                data = ':{} UID {} {} {} {} {} {} 0 +{} {} {} {} :{}'.format(server.sid, u.nickname, hopcount, u.signon, u.ident, u.hostname, u.uid, u.modes, u.cloakhost, u.cloakhost, ip, u.realname)
                newserver._send(data)
                if u.fingerprint:
                    data = 'MD client {} certfp :{}'.format(u.uid, u.fingerprint)
                    newserver._send(':{} {}'.format(server.sid, data))
                if u.operaccount:
                    data = 'MD client {} operaccount :{}'.format(u.uid, u.operaccount)
                    newserver._send(':{} {}'.format(server.sid, data))
                if u.snomasks:
                    newserver._send(':{} BV +{}'.format(u.uid, u.snomasks))
                if 'o' in u.modes:
                    for line in u.swhois:
                        newserver._send(':{} SWHOIS {} :{}'.format(server.sid, u.uid, line))
                if u.away:
                    newserver._send(':{} AWAY :{}'.format(u.uid, u.away))
    except Exception as ex:
        logging.exception(ex)


def syncData(ircd, newserver, local_only=False):
    if ircd.users:
        syncUsers(ircd, newserver, local_only=local_only)
    if ircd.channels:
        syncChannels(ircd, newserver)
    try:
        for type in ircd.tkl:
            for entry in ircd.tkl[type]:
                if not ircd.tkl[type][entry]['global']:
                    continue
                mask = '{} {}'.format(entry.split('@')[0], entry.split('@')[1])
                setter = ircd.tkl[type][entry]['setter']
                try:
                    source = list(filter(lambda s: s.hostname == setter, ircd.servers))
                    if source:
                        if source[0].hostname == newserver.hostname or source[0].introducedBy == newserver:
                            continue
                except Exception:
                    pass
                expire = ircd.tkl[type][entry]['expire']
                ctime = ircd.tkl[type][entry]['ctime']
                reason = ircd.tkl[type][entry]['reason']
                data = ':{} TKL + {} {} {} {} {} :{}'.format(ircd.sid, type, mask, setter, expire, ctime, reason)
                newserver._send(data)
    except Exception as ex:
        logging.exception(ex)
    logging.info('{}Server {} is done syncing to {}, sending EOS.{}'.format(Y, ircd.hostname, newserver.hostname, W))
    newserver._send(':{} EOS'.format(ircd.sid))

    if newserver not in ircd.syncDone:
        cloakhash = ircd.conf['settings']['cloak-key']
        cloakhash = hashlib.md5(cloakhash.encode('utf-8')).hexdigest()
        data = ':{} NETINFO {} {} {} MD5:{} {} 0 0 :{}'.format(ircd.sid, ircd.maxgusers, int(time.time()), ircd.versionnumber.replace('.', ''), cloakhash, ircd.creationtime, ircd.name)
        newserver._send(data)
        ircd.syncDone.append(newserver)

    if not hasattr(newserver, 'outgoing') or not newserver.outgoing:
        newserver._send(':{} PONG {} {}'.format(ircd.sid, newserver.hostname, ircd.hostname))
    else:
        newserver._send(':{} PING {} {}'.format(ircd.sid, ircd.hostname, newserver.hostname))
    return


def validate_server_info(self, client):
    try:
        ip, port = client.socket.getpeername()
        ip2, port2 = client.socket.getsockname()
        if client.hostname not in self.ircd.conf['link']:
            error = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(self.ircd.hostname, ip2, port2)
            client._send(':{} ERROR :{}'.format(self.ircd.sid, error))
            client.quit('no matching link configuration')
            logging.info(f'Link denied for {client.hostname}: server not found in conf')
            return 0

        client.cls = self.ircd.conf['link'][client.hostname]['class']
        logging.info('{}Class: {}{}'.format(G, client.cls, W))
        if not client.cls:
            error = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(self.ircd.hostname, ip2, port2)
            client._send(':{} ERROR :{}'.format(self.ircd.sid, error))
            client.quit('no matching link configuration')
            logging.info(f'Link denied for {client.hostname}: unable to assign class to connection')
            return 0

        totalClasses = list(filter(lambda s: s.cls == client.cls, self.ircd.servers))
        if len(totalClasses) > int(self.ircd.conf['class'][client.cls]['max']):
            client.quit('Maximum server connections for this class reached')
            logging.info(f'Link denied for {client.hostname}: max connections for this class')
            return 0

        if client.linkpass:
            if client.linkpass != self.ircd.conf['link'][client.hostname]['pass']:
                error = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(self.ircd.hostname, ip2, port2)
                client._send(':{} ERROR :{}'.format(self.ircd.sid, error))
                client.quit('no matching link configuration')
                logging.info(f'Link denied for {client.hostname}: incorrect password')
                return 0

        if not is_match(self.ircd.conf['link'][client.hostname]['incoming']['host'], ip):
            error = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(self.ircd.hostname, ip2, port2)
            client._send(':{} ERROR :{}'.format(self.ircd.sid, error))
            client.quit('no matching link configuration')
            logging.info(f'Link denied for {client.hostname}: incoming IP does not match conf')
            return 0

        if client.hostname not in self.ircd.conf['settings']['ulines']:
            for cap in [cap.split('=')[0] for cap in self.ircd.server_support]:
                if cap in client.protoctl:
                    logging.info('Cap {} is supported by both parties'.format(cap))
                else:
                    client._send(':{} ERROR :Server {} is missing support for {}'.format(client.sid, client.hostname, cap))
                    client.quit('Server {} is missing support for {}'.format(client.hostname, cap))
                    logging.info(f'Link denied for {client.hostname}: no matching CAPs')
                    return 0

        if client.linkpass and client.linkpass != self.ircd.conf['link'][client.hostname]['pass']:
            msg = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(client.hostname, ip, port)
            error = 'Error connecting to server {}[{}:{}]: no matching link configuration'.format(self.ircd.hostname, ip2, port2)
            if client not in self.ircd.linkrequester:
                client._send('ERROR :{}'.format(error))
            elif self.ircd.linkrequester[client]['user']:
                self.ircd.linkrequester[client]['user'].send('NOTICE', '*** {}'.format(msg))
            client.quit('no matching link configuration', silent=True)
            logging.info(f'Link denied for {client.hostname}: incorrect password')
            return 0

        return 1
    except Exception as ex:
        logging.exception(ex)
        return 0


class Link(threading.Thread):
    def __init__(self, origin=None, localServer=None, name=None, host=None, port=None, pswd=None, tls=False, autoLink=False):
        threading.Thread.__init__(self)
        self.origin = origin
        self.ircd = localServer
        self.name = name
        self.pswd = pswd
        self.host = host
        self.port = port
        self.tls = tls
        self.autoLink = autoLink
        self.sendbuffer = ''

    def run(self):
        serv = None
        try:
            exists = list(filter(lambda s: s.hostname == self.name, self.ircd.servers + [self.ircd]))
            if exists:
                logging.error('Server {} already exists on this network'.format(exists[0].hostname))
                return

            if not self.host.replace('.', '').isdigit():
                self.host = socket.gethostbyname(self.host)
            self.socket = socket.socket()
            if self.tls:
                self.socket = self.ircd.default_sslctx.wrap_socket(self.socket, server_side=False)
                logging.info('Wrapped outgoing socket {} in TLS'.format(self.socket))

            serv = Server(origin=self.ircd, serverLink=True, sock=self.socket, is_ssl=self.tls)
            serv.hostname = self.name
            serv.ip = self.host
            serv.port = self.port
            serv.outgoing = True
            if self.origin or self.autoLink:
                self.ircd.linkrequester[serv] = self.origin

            # self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))

            selfIntroduction(self.ircd, serv, outgoing=True)

            if serv not in self.ircd.introducedTo:
                self.ircd.introducedTo.append(serv)

        except Exception as ex:
            logging.exception(ex)
            # Outgoing link timed out.
            if serv:
                serv.quit(str(ex))
