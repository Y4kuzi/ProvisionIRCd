from handle.functions import (is_match,
                              TKL,
                              cloak,
                              IPtoBase64,
                              Base64toIP,
                              show_support,
                              check_flood,
                              logging)
from classes.rpl import RPL, ERR
import random
import time
import string
import socket
import importlib
import datetime
import threading
import hashlib
import select
import ipaddress

try:
    import objgraph
except ImportError:
    pass
import gc

gc.enable()


def RevIP(ip):
    x = 3
    revip = ''
    while 1:
        if revip:
            revip = revip + '.' + ip.split('.')[x]
        else:
            revip = ip.split('.')[x]
        if x == 0:
            break
        x -= 1
    return revip


class blacklist_check(threading.Thread):
    def __init__(self, user, blacklist):
        threading.Thread.__init__(self)
        self.user = user
        self.blacklist = blacklist

    def run(self):
        user = self.user
        blacklist = self.blacklist
        # logging.info('Looking up DNSBL query on {}: {}'.format(self.blacklist, user.ip))
        try:
            result = socket.gethostbyname(RevIP(user.ip) + '.' + blacklist)
            reason = 'Your IP is blacklisted by {}'.format(blacklist)
            if user.ip not in user.server.dnsblCache:
                user.server.dnsblCache[user.ip] = {}
                user.server.dnsblCache[user.ip]['bl'] = blacklist
                user.server.dnsblCache[user.ip]['ctime'] = int(time.time())
                msg = '*** DNSBL match for IP {}: {} [nick: {}]'.format(user.ip, blacklist, user.nickname)
                user.server.snotice('d', msg)
            if user in user.server.users:
                user.sendraw(RPL.TEXT, f"* :{reason}")
            user.sendbuffer = []
            user.recvbuffer = []
            user.quit(reason)

        except socket.gaierror:  # socket.gaierror: [Errno -2] Name or service not known -> no match.
            pass

        except Exception as ex:
            logging.exception(ex)


def DNSBLCheck(self):
    user = self
    ircd = user.server
    if user.ip in ircd.dnsblCache:
        reason = 'Your IP is blacklisted by {}'.format(ircd.dnsblCache[user.ip]['bl'] + ' [cached]')
        for u in iter([u for u in list(ircd.users) if u.ip == user.ip]):
            u.sendraw(RPL.TEXT, f"* :{reason}")
            u.sendbuffer = ''
            u.recvbuffer = ''
            u.quit(reason)
        return
    if user.ip in ircd.bannedList:
        user._send(f':{ircd.hostname} {RPL.TEXT} * :Your IP has been banned (listed locally).')
        user.sendbuffer = ''
        user.recvbuffer = ''
        user.quit('Your IP has been banned (listed locally)')
        return

    for x in iter([x for x in ircd.conf['dnsbl']['list'] if '.' in x]):
        if user in user.server.users:
            b = blacklist_check(user, x)
            b.start()

"""
READ_ONLY = (
        select.POLLIN |
        READ_ONLY        select.POLLPRI |
        select.POLLHUP |
        select.POLLERR
)
READ_WRITE =  | select.POLLOUT
"""

def resolve_ip(self):
    ip = self.ip if self.ip.replace('.', '').isdigit() else self.ip[7:]

    try:
        ip_resolved = socket.gethostbyaddr(ip)[0]
    except socket.herror:  # Not a typo.
        ip_resolved = ip
    except Exception as ex:
        logging.exception(ex)

    deny_except = False
    if 'except' in self.server.conf and 'deny' in self.server.conf['except']:
        for e in self.server.conf['except']['deny']:
            if is_match(e, self.ident + '@' + ip_resolved):
                deny_except = True
                break
    if not deny_except:
        for entry in self.server.deny:
            if is_match(entry, self.ident + '@' + ip_resolved):
                self.server.deny_cache[ip] = {}
                self.server.deny_cache[ip]['ctime'] = int(time.time())
                self.server.deny_cache[ip]['reason'] = self.server.deny[entry] if self.server.deny[entry] else ''
                if self.server.deny_cache[ip]['reason']:
                    self.server.notice(self, '* Connection denied: {}'.format(self.server.deny_cache[ip]['reason']))
                return self.quit('Your host matches a deny block, and is therefore not allowed.')


class User:
    def __init__(self, server, sock=None, address=None, is_ssl=None, server_class=None, params=None):
        try:
            self.socket = sock
            self.server = None
            self.cloakhost = '*'
            self.connected = True
            self.nickname = '*'
            self.ident = ''
            self.hostname = ''
            self.realname = ''
            self.svid = '*'
            self.channels = []
            self.modes = ''
            self.operflags = []
            self.snomasks = ''
            self.swhois = []
            self.watchlist = []
            self.monlist = []
            self.caplist = []
            self.backbuffer = []
            self.sends_cap = False
            self.cap_end = False
            self.watchC = False
            self.watchS = False
            self.ssl = is_ssl

            self.operaccount = ''
            self.away = False
            self.sendbuffer = ''
            self.operswhois = ''
            self.fingerprint = None

            self.flood_penalty = 0
            self.flood_penalty_time = 0

            if self.socket:
                self.server = server
                self.ircd = server
                self.addr = address
                self.ip, self.hostname = self.addr[0], self.addr[0]
                if self.ip.startswith('::ffff:') and self.ip[7:].replace('.', '').isdigit():
                    # logging.debug('Invalid IPv6, using {}'.format(self.ip[7:]))
                    self.ip = self.ip[7:]
                if self.hostname.startswith('::ffff:') and self.hostname[7:].replace('.', '').isdigit():
                    # logging.debug('Invalid IPv6, using {}'.format(self.ip[7:]))
                    self.hostname = self.hostname[7:]

                self.cls = None
                self.signon = int(time.time())
                self.registered = False
                self.ping = int(time.time())
                self.recvbuffer = []
                self.validping = False
                self.server_pass_accepted = False
                self.uid = '{}{}'.format(self.ircd.sid, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)))
                while [u for u in self.ircd.users if hasattr(u, 'uid') and u != self and u.uid == self.uid]:
                    self.uid = '{}{}'.format(self.ircd.sid, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6)))

                self.lastPingSent = time.time() * 1000
                self.lag_measure = self.lastPingSent

                self.ircd.users.append(self)
                for callable in [callable for callable in server.hooks if callable[0].lower() == 'new_connection']:
                    try:
                        callable[2](self.ircd, self)
                    except Exception as ex:
                        logging.exception(ex)
                if 'dnsbl' in self.ircd.conf and self.ip.replace('.', '').isdigit() and not ipaddress.ip_address(self.ip).is_private:
                    # self.sendraw('020', ':Please wait while we process your connection.')
                    dnsbl_except = False
                    if 'except' in self.ircd.conf and 'dnsbl' in self.ircd.conf['except']:
                        for e in self.ircd.conf['except']['dnsbl']:
                            if is_match(e, self.ip):
                                dnsbl_except = True
                                break
                    if not dnsbl_except:
                        DNSBLCheck(self)

                TKL.check(self.ircd, self, 'z')
                TKL.check(self.ircd, self, 'Z')

                throttleTreshhold = int(self.ircd.conf['settings']['throttle'].split(':')[0])
                throttleTime = int(self.ircd.conf['settings']['throttle'].split(':')[1])
                total_conns = [u for u in self.ircd.throttle if u.ip == self.ip and int(time.time()) - self.ircd.throttle[u]['ctime'] <= throttleTime]
                throttle_except = False
                if 'except' in self.ircd.conf and 'throttle' in self.ircd.conf['except']:
                    for e in self.ircd.conf['except']['throttle']:
                        if is_match(e, self.ip):
                            throttle_except = True
                            break
                if len(total_conns) >= throttleTreshhold and not throttle_except:
                    self.quit('Throttling - You are (re)connecting too fast')

                unknown_conn = [user for user in self.ircd.users if user.ip == self.ip and not user.registered]
                if len(unknown_conn) >= 5:
                    self.quit('Too many unknown connections from your IP')

                self.ircd.throttle[self] = {}
                self.ircd.throttle[self]['ip'] = self.ip
                self.ircd.throttle[self]['ctime'] = int(time.time())
                self.ircd.totalcons += 1

                if self.ssl and self.socket:
                    try:
                        fp = self.socket.getpeercert(binary_form=True)
                        if fp:
                            self.fingerprint = hashlib.sha256(repr(fp).encode('utf-8')).hexdigest()
                    except Exception as ex:
                        logging.exception(ex)

                self.idle = int(time.time())
                if self.ip in self.ircd.hostcache:
                    self.hostname = self.ircd.hostcache[self.ip]['host']
                    self._send(':{u.server.hostname} NOTICE AUTH :*** Found your hostname ({u.hostname}) [cached]'.format(u=self))
                elif 'dontresolve' not in self.ircd.conf['settings'] or ('dontresolve' in self.ircd.conf['settings'] and not self.ircd.conf['settings']['dontresolve']):
                    try:
                        self.hostname = socket.gethostbyaddr(self.ip)[0]
                        if not self.hostname.split('.')[1]:
                            raise
                        self.ircd.hostcache[self.ip] = {}
                        self.ircd.hostcache[self.ip]['host'] = self.hostname
                        self.ircd.hostcache[self.ip]['ctime'] = int(time.time())
                        self._send(':{u.server.hostname} NOTICE AUTH :*** Found your hostname ({u.hostname})'.format(u=self))
                    except Exception:
                        self.hostname = self.ip
                        self._send(':{u.server.hostname} NOTICE AUTH :*** Couldn\'t resolve your hostname; using IP address instead ({u.hostname})'.format(u=self))
                else:
                    self._send(':{u.server.hostname} NOTICE AUTH :*** Host resolution is disabled, using IP ({u.ip})'.format(u=self))

                TKL.check(self.ircd, self, 'g')
                TKL.check(self.ircd, self, 'G')
                self.cloakhost = cloak(self)

            else:
                try:
                    self.ircd = server_class
                    self.ircd.users.append(self)
                    self.cls = 0
                    self.nickname = params[2]
                    self.idle = int(params[4])
                    self.signon = int(params[4])
                    self.ident = params[5]
                    self.hostname = params[6]
                    self.uid = params[7]
                    server = list(filter(lambda s: s.sid == params[0][1:], self.ircd.servers))
                    if not server:
                        logging.debug(f'Quitting {self.nickname} because their server does not exist')
                        self.quit('Unknown connection')
                        return
                    self.server = server[0]
                    self.modes = params[9].strip('+')
                    if params[11] == '*':
                        self.cloakhost = params[6]
                    else:
                        self.cloakhost = params[11]
                    if params[12] != '*' and not params[12].replace('.', '').isdigit() and params[12] is not None:
                        self.ip = Base64toIP(params[12])
                    else:
                        self.ip = params[12]
                    self.realname = ' '.join(params[13:])[1:]
                    self.registered = True
                    TKL.check(self.ircd, self, 'Z')
                    TKL.check(self.ircd, self, 'G')
                    if len(self.ircd.users) > self.ircd.maxgusers:
                        self.ircd.maxgusers = len(self.ircd.users)

                    for callable in [callable for callable in self.ircd.hooks if callable[0].lower() == 'remote_connect']:
                        try:
                            callable[2](self.ircd, self)
                        except Exception as ex:
                            logging.exception(ex)

                    watch_notify = iter([user for user in self.ircd.users if self.nickname.lower() in [x.lower() for x in user.watchlist]])
                    for user in watch_notify:
                        user.sendraw(RPL.LOGON, '{} {} {} {} :logged online'.format(self.nickname, self.ident, self.cloakhost, self.signon))

                except Exception as ex:
                    logging.exception(ex)
            # logging.info('New user class {} successfully created'.format(self))
            gc.collect()

        except Exception as ex:
            logging.exception(ex)

    def handle_recv(self):
        try:
            for entry in list(self.recvbuffer):
                time_to_execute, recv = entry
                if int(time.time()) >= time_to_execute or 'o' in self.modes:
                    self.recvbuffer.remove(entry)
                    recv = recv.rstrip(' \n\r')
                    if not recv:
                        continue

                    ircd = self.server
                    command = recv.split()[0].lower()
                    self.ping = int(time.time())
                    if not hasattr(self, 'flood_safe') or not self.flood_safe:
                        self.flood_penalty += 1000 + len(recv)
                    check_flood(ircd, self)

                    if not self.flood_penalty_time:
                        self.flood_penalty_time = int(time.time())

                    dont_parse = ['topic', 'swhois', 'prop']
                    if command in dont_parse:
                        parsed = recv.split(' ')
                    else:
                        parsed = self.parse_command(recv)

                    pre_reg_cmds = ['nick', 'user', 'pass', 'pong', 'cap', 'starttls', 'webirc']

                    if not self.registered and self.cls and not self.server_pass_accepted and 'password' in ircd.conf['allow'][self.cls] and command not in ['pass', 'cap']:
                        return self.quit('Password required')

                    ignore = ['ping', 'pong', 'ison', 'watch', 'who', 'privmsg', 'notice', 'ns', 'cs', 'nickserv', 'chanserv', 'id', 'identify', 'login', 'auth']
                    # ignore = []
                    if command not in ignore:
                        pass

                    # Looking for API calls.
                    if not self.registered:
                        for callable in [callable for callable in self.server.api if callable[0].lower() == command]:
                            api_func = callable[1]
                            api_host = callable[2]
                            api_password = callable[3]
                            if api_host and not is_match(api_host, self.ip):
                                self.quit('API', api=True)
                                break
                            if api_password and recv[1] != api_password:
                                self.quit('API', api=True)
                                break
                            api_func(self, ircd, parsed)
                            self.quit('API', api=True)
                            return

                    # print('ik ga zo slaaaaaapen maar jij bent ernie?')
                    if type(self).__name__ == 'User' and command not in pre_reg_cmds and not self.registered:
                        return self.sendraw(ERR.NOTREGISTERED, 'You have not registered')
                    if command == 'pong':
                        if self in self.server.pings:
                            ping = recv.split()[1]
                            if ping.startswith(':'):
                                ping = ping[1:]
                            if self.server.pings[self] == ping:
                                del self.server.pings[self]
                                self.validping = True
                                if self.ident != '' and self.nickname != '*' and (self.cap_end or not self.sends_cap):
                                    self.welcome()
                            else:
                                return self.quit('Unauthorized connection')

                    try:
                        cmd = importlib.import_module('cmds.cmd_' + command.lower())
                        getattr(cmd, 'cmd_' + command.upper())(self, ircd, parsed)
                        continue
                    except ImportError:
                        try:
                            alias = ircd.conf['aliases']
                            if alias[command.lower()]['type'] == 'services':
                                service = list(filter(lambda u: u.nickname == alias[command.lower()]['target'] and 'services' in ircd.conf['settings'] and u.server.hostname == ircd.conf['settings']['services'], ircd.users))
                                if not service:
                                    return self.sendraw(ERR.SERVICESDOWN, ':Services are currently down. Please try again later.')
                            data = '{} :{}'.format(alias[command.lower()]['target'], ' '.join(recv.split()[1:]))
                            self.handle('PRIVMSG', data)
                            continue
                        except KeyError:
                            pass

                    # pre_command hook.
                    allow = 1
                    for callable in [callable for callable in self.server.hooks if callable[0].lower() == 'pre_command' and callable[1].lower() == command.lower()]:
                        try:
                            allow = callable[2](self, ircd, parsed)
                        except Exception as ex:
                            logging.exception(ex)
                    if not allow and allow is not None:
                        continue

                    if command.lower() not in ['admin', 'part', 'quit', 'ping', 'pong'] and self.registered and TKL.check(self.server, self, 's'):
                        return

                    false_cmd = True
                    c = next((x for x in ircd.command_class if command.upper() in list(x.command)), None)
                    if c:
                        false_cmd = False
                        if c.check(self, parsed):
                            c.execute(self, parsed)  # <--- instant reply from /stats u (where psutil.Process() is being called)
                            # threading.Thread(target=c.execute, args=([self, parsed])).start() # ~1 second delay in /stats u

                    if false_cmd:
                        self.sendraw(ERR.UNKNOWNCOMMAND, '{} :Unknown command'.format(command.upper()))

        except Exception as ex:
            logging.exception(ex)

    @staticmethod
    def parse_command(data):
        xwords = data.split(' ')
        words = []
        for i in range(len(xwords)):
            word = xwords[i]
            if word.startswith(':'):
                words.append(' '.join([word[1:]] + xwords[i + 1:]))
                break
            words.append(word)
        words = list(filter(None, words))
        return words

    def _send(self, data):
        if not hasattr(self, 'socket'):
            # logging.debug('Socket {} got sent flashed out.'.format(self))
            return
        if self.socket:
            self.sendbuffer += data + '\r\n'
            # if self.server.use_poll:
            #    logging.debug('Flag for {} set to READ_WRITE (_send())'.format(self))
            #    self.server.pollerObject.modify(self.socket, READ_WRITE)

    def send(self, command, data):
        if not self.socket:
            return

        # full_data = f':{self.server.hostname} {command} {self.nickname} {data}'
        # self._send(full_data)
        # return

        # Experimental. Comment out above 3 lines in case of issues.
        def send_data():
            data = ' '.join(buffer).split(data_prefix)[1].lstrip()
            if prepend_colon and not data[0].startswith(':'):
                data = ':' + ''.join(data).lstrip()
            full_data = data_prefix + data
            if len(full_data) >= max_buff:
                full_data = full_data[:max_buff]
                # logging.debug(f'Sending data trimmed: {len(full_data)}')
            self._send(full_data)

        max_buff = 510  # 2 reserved for \r\n
        full_data = f':{self.server.hostname} {command} {self.nickname} {data}'
        data_prefix = full_data.split(data)[0]  # .rstrip()
        prepend_colon = True if data.startswith(':') else False
        buffer = []
        for i, word in enumerate(full_data.split()):
            buffer.append(word)
            buffer_size = len(' '.join(buffer))
            if len(full_data.split()) > i + 1:
                next_buffer_size = buffer_size + len(full_data.split()[i + 1])
                if next_buffer_size >= max_buff:
                    if buffer == data_prefix.rstrip().split():  # Original line was too long.
                        buffer = [full_data]
                    send_data()
                    if buffer != [full_data]:
                        buffer = [data_prefix]
                    else:
                        buffer = []
                        break
                    continue
        if buffer:
            send_data()

    def sendraw(self, numeric, data):
        if type(numeric).__name__ in ['RPL', 'ERR']:
            numeric = numeric.value
        '''
        for callable in [h for h in self.server.hooks if h[0].lower() == 'rpl' and int(h[1]) == int(numeric)]:
            try:
                reply = callable[2](self)
                self.send(str(numeric).rjust(3, '0'), reply)
            except Exception as ex:
                logging.exception(ex)
        '''
        self.send(str(numeric).rjust(3, '0'), data)

    def broadcast(self, users: list, data: str, source=None):
        if source:
            if type(source).__name__ == 'Server':
                source = source.hostname
            else:
                source.flood_penalty += 10000
                source = source.fullmask()
        else:
            source = self.fullmask()
            self.flood_penalty += 10000

        for user in users:
            user._send(':{} {}'.format(source, data))

    def setinfo(self, info, t='', source=None):
        try:
            if not info or not t:
                return
            if not source:
                return logging.error('No source provided in setinfo()!')
            if type(source) == str or type(source).__name__ != 'Server':
                return logging.error('Wrong source type provided in setinfo(): {}'.format(source))
            if t not in ['host', 'ident', 'gecos']:
                return logging.error('Incorrect type received in setinfo(): {}'.format(t))
            updated = []
            if self.registered and t in ['host', 'ident']:
                valid = 'abcdefghijklmnopqrstuvwxyz0123456789.-'
                for c in str(info):
                    if c.lower() not in valid:
                        info = info.replace(c, '')
                    if not info:
                        return
                for user in iter([user for user in self.ircd.users if 'chghost' in user.caplist and user not in updated and user.socket]):
                    common_chan = list(filter(lambda c: user in c.users and self in c.users, self.ircd.channels))
                    if not common_chan:
                        continue
                    user._send(':{} CHGHOST {} {}'.format(self.fullmask(), info if t == 'ident' else self.ident, info if t == 'host' else self.cloakhost))
                    updated.append(user)

            if t == 'host':
                cmd = 'SETHOST'
            elif t == 'ident':
                cmd = 'SETIDENT'
            elif t == 'gecos':
                cmd = 'SETNAME'
            data = ':{} {} {}'.format(self.uid, cmd, info)
            self.ircd.new_sync(source, data)
            if t == 'host':
                self.cloakhost = info
            elif t == 'ident':
                self.ident = info
            elif t == 'gecos':
                self.realname = info
        except Exception as ex:
            logging.exception(ex)

    def welcome(self):
        if not self.registered:
            for callable in [callable for callable in self.server.hooks if callable[0].lower() == 'pre_local_connect']:
                try:
                    success = callable[2](self.server, self)
                    if not success and success is not None:  # Modules need to explicitly return False or 0, not the default None.
                        logging.debug(f"Connection process denied for user {self} by module: {callable}")
                        return
                except Exception as ex:
                    logging.exception(ex)

            deny, reason = 0, ''
            if self.ip in self.server.deny_cache:
                deny = 1
                if 'reason' in self.server.deny_cache[self.ip]:
                    reason = self.server.deny_cache[self.ip]['reason']

            deny_except = False
            if 'except' in self.server.conf and 'deny' in self.server.conf['except']:
                for e in self.server.conf['except']['deny']:
                    if is_match(e, self.ident + '@' + self.ip) or is_match(e, self.ident + '@' + self.hostname):
                        deny_except = True
                        break

            if not deny_except and not deny:
                for entry in self.server.deny:
                    if is_match(entry, self.ident + '@' + self.ip) or is_match(entry, self.ident + '@' + self.hostname):
                        self.server.deny_cache[self.ip] = {}
                        self.server.deny_cache[self.ip]['ctime'] = int(time.time())
                        reason = self.server.deny[entry] if self.server.deny[entry] else ''
                        self.server.deny_cache[self.ip]['reason'] = reason
                        logging.info('Denied client {} with match: {} [{}]'.format(self, entry, reason))
                        deny = 1
                        break

            if deny:
                if reason:
                    self.server.notice(self, '* Connection denied: {}'.format(reason))
                return self.quit('Your host matches a deny block, and is therefore not allowed.')

            block = 0
            for cls in iter([cls for cls in self.server.conf['allow'] if cls in self.server.conf['class']]):
                t = self.server.conf['allow'][cls]
                isMatch = False
                if 'ip' in t:
                    clientmask = '{}@{}'.format(self.ident, self.ip)
                    isMatch = is_match(t['ip'], clientmask)
                if 'hostname' in t and not isMatch:  # Try with hostname. IP has higher priority.
                    clientmask = '{}@{}'.format(self.ident, self.hostname)
                    isMatch = is_match(t['hostname'], clientmask)
                if isMatch:
                    if 'options' in t:
                        if 'ssl' in t['options'] and not self.ssl:
                            continue
                    self.cls = cls
                    if 'block' in t:
                        for entry in t['block']:
                            clientmask_ip = '{}@{}'.format(self.ident, self.ip)
                            clientmask_host = '{}@{}'.format(self.ident, self.hostname)
                            block = is_match(entry, clientmask_ip) or is_match(entry, clientmask_host)
                            if block:
                                logging.info('Client {} blocked by {}: {}'.format(self, cls, entry))
                                break
                    break

            if not self.cls or block:
                return self.quit('You are not authorized to connect to this server')

            totalClasses = list(filter(lambda u: u.server == self.server and u.cls == self.cls, self.server.users))
            if len(totalClasses) > int(self.server.conf['class'][self.cls]['max']):
                return self.quit('Maximum connections for this class reached')

            clones = [u for u in self.server.users if u.socket and u.ip == self.ip]
            if len(clones) >= int(self.server.conf['allow'][self.cls]['maxperip']):
                return self.quit('Maximum connections from your IP')

            # Resolve IP in the background to test against deny-block matches, if host resolution is disabled.
            if 'dontresolve' in self.server.conf['settings']:
                threading.Thread(target=resolve_ip, args=([self])).start()

            if not hasattr(self, 'socket'):
                return
            self.sendraw(RPL.WELCOME, ':Welcome to the {} IRC Network {}!{}@{}'.format(self.server.name, self.nickname, self.ident, self.hostname))
            self.sendraw(RPL.YOURHOST, ':Your host is {}, running version {}'.format(self.server.hostname, self.server.version))
            d = datetime.datetime.fromtimestamp(self.server.creationtime).strftime('%a %b %d %Y')
            t = datetime.datetime.fromtimestamp(self.server.creationtime).strftime('%H:%M:%S %Z')
            self.sendraw(RPL.CREATED, ':This server was created {} at {}'.format(d, t))

            umodes, chmodes = '', ''
            for m in iter([m for m in self.server.user_modes if m.isalpha() and m not in umodes]):
                umodes += m
            for t in self.server.channel_modes:
                for m in iter([m for m in self.server.channel_modes[t] if m.isalpha() and m not in chmodes]):
                    chmodes += m
            umodes = ''.join(sorted(set(umodes)))
            chmodes = ''.join(sorted(set(chmodes)))

            self.sendraw(RPL.MYINFO, '{} {} {} {}'.format(self.server.hostname, self.server.version, umodes, chmodes))
            show_support(self, self.server)
            cipher = None
            if self.ssl and hasattr(self.socket, 'cipher') and self.socket.cipher:
                if self.socket.cipher():
                    cipher, tls_version, secret_bits = self.socket.cipher()
                    self.send('NOTICE', ':*** You are connected to {} with {}-{}'.format(self.server.hostname, self.socket.version(), cipher))

            msg = '*** Client connecting: {u.nickname} ({u.ident}@{u.hostname}) {{{u.cls}}} [{0}{1}]'.format('secure' if self.ssl else 'plain', '' if not cipher else ' ' + cipher, u=self)
            self.server.snotice('c', msg)

            binip = IPtoBase64(self.ip) if self.ip.replace('.', '').isdigit() else self.ip
            data = '{s.nickname} {s.server.hopcount} {s.signon} {s.ident} {s.hostname} {s.uid} 0 +{s.modes} {s.cloakhost} {s.cloakhost} {0} :{s.realname}'.format(binip, s=self)
            self.server.new_sync(self.server, ':{} UID {}'.format(self.server.sid, data))

            self.registered = True

            current_lusers = len([user for user in self.server.users if user.server == self.server and user.registered])
            if current_lusers > self.server.maxusers:
                self.server.maxusers = current_lusers

            if len(self.server.users) > self.server.maxgusers:
                self.server.maxgusers = len(self.server.users)
                if self.server.maxgusers % 10 == 0:
                    self.server.snotice('s', '*** New global user record: {}'.format(self.server.maxgusers))

            self.handle('lusers')
            self.handle('motd')
            for callable in [callable for callable in self.server.hooks if callable[0].lower() == 'welcome']:
                try:
                    callable[2](self, self.server)
                except Exception as ex:
                    logging.exception(ex)
            if self.fingerprint:
                self.send('NOTICE', ':*** Your TLS fingerprint is {}'.format(self.fingerprint))
                data = 'MD client {} certfp :{}'.format(self.uid, self.fingerprint)
                self.server.new_sync(self.server, ':{} {}'.format(self.server.sid, data))

            modes = []
            for mode in self.server.conf['settings']['modesonconnect']:
                if mode in self.server.user_modes and mode not in 'oqrzS':
                    modes.append(mode)
            if self.ssl and hasattr(self.socket, 'cipher'):
                modes.append('z')
            if len(modes) > 0:
                p = {'override': True}
                self.handle('mode', '{} +{}'.format(self.nickname, ''.join(modes)), params=p)

            watch_notify = iter([user for user in self.server.users if self.nickname.lower() in [x.lower() for x in user.watchlist]])
            for user in watch_notify:
                user.sendraw(RPL.LOGON, '{} {} {} {} :logged online'.format(self.nickname, self.ident, self.cloakhost, self.signon))

            for callable in [callable for callable in self.server.hooks if callable[0].lower() == 'local_connect']:
                try:
                    callable[2](self.server, self)
                except Exception as ex:
                    logging.exception(ex)

        gc.collect()

    def __repr__(self):
        return "<User '{}:{}'>".format(self.fullmask(), self.server.hostname)

    def fileno(self):
        return self.socket.fileno()

    def fullmask(self):
        if not hasattr(self, 'cloakhost'):
            self.cloakhost = '*'
        return '{}!{}@{}'.format(self.nickname, self.ident, self.cloakhost)

    def fullrealhost(self):
        host = self.hostname if self.hostname else self.ip
        return '{}!{}@{}'.format(self.nickname, self.ident if self.ident != '' else '*', host)

    def chlevel(self, channel):
        if self.server.hostname.lower() in set(self.ircd.conf['settings']['ulines']):
            return 10000
        elif self not in set(channel.users):
            return 0
        elif 'q' in channel.usermodes[self]:
            return 5
        elif 'a' in channel.usermodes[self]:
            return 4
        elif 'o' in channel.usermodes[self]:
            return 3
        elif 'h' in channel.usermodes[self]:
            return 2
        elif 'v' in channel.usermodes[self]:
            return 1
        else:
            return 0

    def ocheck(self, mode, flag):
        ircd = self.server if self.socket else self.ircd
        if (mode in self.modes and flag in self.operflags) or self.server.hostname.lower() in ircd.conf['settings']['ulines']:
            return True
        return False

    def quit(self, reason, error=True, banmsg=None, kill=False, silent=False, api=False, squit=False):  # Why source?
        try:
            if not hasattr(self, 'socket'):
                self.socket = None
            self.recvbuffer = []
            self.backbuffer = []
            ircd = self.ircd if not self.socket else self.server
            sourceServer = self.server if (self.server.socket or self.server == ircd) else self.server.uplink
            if self.registered:
                logging.debug('User {} quit. Uplink source: {}'.format(self.nickname, sourceServer))
            for callable in [callable for callable in ircd.hooks if callable[0].lower() == 'pre_local_quit']:
                try:
                    callable[2](self, ircd)
                except Exception as ex:
                    logging.exception(ex)

            if banmsg:
                ircd.notice(self, '*** You are banned from this server: {}'.format(banmsg))

            if int(time.time()) - self.signon < 60 and self.registered and not error and self.socket:
                reason = str(ircd.conf['settings']['quitprefix']).strip()
                if reason.endswith(':'):
                    reason = reason[:-1]
                reason += ': ' + self.nickname

            if self.socket and reason and not api:
                self._send('ERROR :Closing link: [{}] ({})'.format(self.hostname, reason))

            while self.sendbuffer:
                # logging.info('User {} has sendbuffer remaining: {}'.format(self, self.sendbuffer.rstrip()))
                try:
                    sent = self.socket.send(bytes(self.sendbuffer + '\n', 'utf-8'))
                    self.sendbuffer = self.sendbuffer[sent:]
                except Exception:
                    break

            if self in ircd.pings:
                del ircd.pings[self]

            if self.registered and (self.server == ircd or self.server.eos):
                if reason and not kill:
                    skip = [sourceServer]
                    if squit:
                        for server in [server for server in ircd.servers if hasattr(server, 'protoctl') and 'NOQUIT' in server.protoctl]:  # and not server.eos]:
                            skip.append(server)
                    ircd.new_sync(skip, ':{} QUIT :{}'.format(self.uid, reason))

                if self.socket and reason and not silent:
                    ircd.snotice('c', '*** Client exiting: {} ({}@{}) ({})'.format(self.nickname, self.ident, self.hostname, reason))

            self.registered = False

            for channel in iter([channel for channel in self.channels if 'j' in channel.modes]):
                self.handle('PART', '{}'.format(channel.name))
                continue

            # Check module hooks for visible_in_channel()

            # FIX: [05:57:26] * vknzvmwlcrcdzz (vknzvmwlcrcd@dbe29a0e.364475e1.83c16263.IP) Quit (Write error: [Errno 110] Connection timed out)
            # IN STATUS WINDOW?

            all_broadcast = [self]
            for channel in self.channels:
                for user in channel.users:
                    if user not in all_broadcast and user != self:
                        all_broadcast.append(user)
            inv_checked = 0
            for u in iter([u for u in all_broadcast if u != self]):
                visible = 0
                for channel in iter([chan for chan in self.channels if not visible]):
                    for callable in [callable for callable in ircd.hooks if callable[0].lower() == 'visible_in_channel']:
                        try:
                            visible = callable[2](u, ircd, self, channel)
                            inv_checked = 1
                            # logging.debug('Is {} visible for {} on {}? :: {}'.format(self.nickname, u.nickname, channel.name, visible))
                        except Exception as ex:
                            logging.exception(ex)
                    if visible:  # Break out of the channels loop. No further checks are required.
                        break
                if not visible and inv_checked:
                    logging.debug('User {} is not allowed to see {} on any channel, not sending quit.'.format(u.nickname, self.nickname))
                    all_broadcast.remove(u)

            if self.nickname != '*' and self.ident != '' and reason:
                self.broadcast(all_broadcast, 'QUIT :{}'.format(reason))

            for channel in list(self.channels):
                channel.users.remove(self)
                del channel.usermodes[self]
                self.channels.remove(channel)
                if len(channel.users) == 0 and 'P' not in channel.modes:
                    ircd.channels.remove(channel)
                    del ircd.chan_params[channel]
                    for callable in [callable for callable in ircd.hooks if callable[0].lower() == 'channel_destroy']:
                        try:
                            callable[2](self, ircd, channel)
                        except Exception as ex:
                            logging.exception(ex)

            watch_notify_offline = iter([user for user in ircd.users if self.nickname.lower() in [x.lower() for x in user.watchlist]])
            for user in watch_notify_offline:
                user.sendraw(RPL.LOGOFF, '{} {} {} {} :logged offline'.format(self.nickname, self.ident, self.cloakhost, self.signon))

            if self in ircd.users:
                ircd.users.remove(self)

            if self.socket:
                if ircd.use_poll:
                    ircd.pollerObject.unregister(self.socket)
                try:
                    self.socket.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                self.socket.close()

            hook = 'local_quit' if self.server == ircd else 'remote_quit'
            for callable in [callable for callable in ircd.hooks if callable[0].lower() == hook]:
                try:
                    callable[2](ircd, self)
                except Exception as ex:
                    logging.exception(ex)

            gc.collect()
            del gc.garbage[:]

            if not ircd.forked:
                try:
                    logging.debug('Growth after self.quit() (if any):')
                    objgraph.show_growth(limit=10)
                except:  # Prevent weird spam shit.
                    pass

            del self

        except Exception as ex:
            logging.exception(ex)

    def handle(self, command, data=None, params=None):
        recv = '{} {}'.format(command, data if data else '')
        parsed = self.parse_command(recv)
        command = command.split()[0].lower()
        ircd = self.server if self.socket else self.ircd

        c = next((x for x in ircd.command_class if command.upper() in list(x.command)), None)
        if c:
            try:
                if c.check(self, parsed):
                    if not params:
                        c.execute(self, parsed)
                    else:
                        c.execute(self, parsed, **params)
            except Exception as ex:
                logging.exception(ex)

    def __del__(self):
        # pass
        logging.debug('User {} closed'.format(self))
        # objgraph.show_most_common_types()
