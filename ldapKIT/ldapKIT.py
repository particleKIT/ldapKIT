#!/usr/bin/env python3
import base64
import ldap
import os
from collections import defaultdict
import sys
import hashlib
import logging
from email.utils import parseaddr
# from pretty_bad_protocol.gnupg import GPG
from subprocess import Popen, PIPE, STDOUT
from distutils.util import strtobool
from datetime import datetime
from xkcdpass import xkcd_password as xp
import gitlab
import smtplib

from .config import Config

class Connection:
    def __init__(self,configfile="config.yml", gpg_passphrase=None, dryrun=None):
        self.config = Config(configfile)
        self.dryrun = dryrun
        if not self.config.load():
            sys.exit(1)
        self.ldap = ldap.initialize(self.config['ldap_host'], bytes_mode=False)
        if str(self.config['admin_pw']).split('.')[-1] == 'gpg':
            admin_pw = get_admin_pw(self.config['admin_pw'], gpg_passphrase)
        else:
            admin_pw = self.config['admin_pw']
        try:
            self.ldap.simple_bind_s(
                    self.config['admin_dn'],
                    admin_pw
                    )
        except ldap.SERVER_DOWN:
            logging.error('LDAP server %s is not reachable.' % self.config['ldap_host'])
            sys.exit(1)

        admin_pw = None

    """
    search result object:
    res = [('dn', attrs), ... ]
    attrs = { 'attr1' = ['value1'], ... }
    """
    def search(self, dn, sfilter, attr=[]):
        res = self.ldap.search_s(
                dn + ',' + self.config['ldap_realm'],
                ldap.SCOPE_SUBTREE,
                sfilter,
                attr
                )
        if len(res) == 0:
            logging.info('No result for ' + sfilter + ' on ' + dn)
            return False
        if len(res) > 1:
            logging.info(str(len(res)) + ' results for ' + sfilter + ' on ' + dn)
        return res

    def user_exists(self, user, dn=False):
        if type(user) == bytes:
            user = user.decode()
        if not dn:
            return self.search("ou=People", "(uid=%s)" % user)
        try:
            return self.ldap.search_s(user, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            return False

    def group_exists(self, group):
        return self.search("ou=Group", "(cn=%s)" % group)

    def get_user_attr(self,user,attr=[]):
        user = self.search('ou=People',"(uid=%s)" % user, attr)
        if not user:
            logging.error("User does not exist.")
            return False
        try:
            r = dict(map(lambda u: (u[0], u[1][0].decode('utf-8')) if len(u[1]) == 1 else (u[0], [f.decode("utf-8") for f in u[1]]), user[0][1].items()))
            if len(attr) > 0:
                r = { a : r.get(a,None) for a in attr }
            return r
        except:
            raise Exception("The LDAP search return format was unexpected.")

    def get_gid(self, group):
        res = self.search('ou=Group',"(cn=%s)" % group, ['gidNumber'])
        if not res or len(res) > 1:
            logging.error("Group does not exists or is not unique.")
            return False
        try:
            gid = res[0][1]['gidNumber'][0]
        except:
            raise Exception("The LDAP search return format was unexpected.")
        return gid

    def get_group(self, gid):
        res = self.search('ou=Group',"(gidNumber=%s)" % str(gid), ['cn'])
        if res and len(res) == 1:
            try:
                return res[0][1]['cn'][0]
            except:
                raise Exception("The LDAP search return format was unexpected.")

    def get_next_gid(self):
        res = self.search('ou=Group', "(objectClass=posixGroup)", ['gidNumber'])
        maxgid = self.config['id_range']['gid']['min']
        try:
            for group in res:
                maxgid = max(maxgid, int(group[1]['gidNumber'][0])) \
                        if int(group[1]['gidNumber'][0]) < int(self.config['id_range']['gid']['unmanaged']) \
                        else maxgid
        except:
            raise Exception("The LDAP search return format was unexpected.")
        assert maxgid < self.config['id_range']['gid']['max']
        return maxgid+1

    def get_next_uid(self):
        res = self.search('ou=People', "(objectClass=posixAccount)", ['uidNumber'])
        maxuid = self.config['id_range']['uid']['min']
        try:
            for user in res:
                maxuid = max(maxuid, int(user[1]['uidNumber'][0])) \
                        if int(user[1]['uidNumber'][0]) < int(self.config['id_range']['uid']['unmanaged']) \
                        else maxuid
        except:
            raise Exception("The LDAP search return format was unexpected.")
        assert maxuid < self.config['id_range']['uid']['max']
        return maxuid+1

    def remove_dead_entries(self, noninteractive=False):
        res = self.ldap.search_s("ou=Group," + self.config['ldap_realm'], ldap.SCOPE_SUBTREE)
        groups_members = {x[1]['cn'][0]: x[1]['member'] for x in res if 'cn' in x[1]}

        users_dead  = defaultdict(list)
        users_alive = []
        groups_dead = []
        for group, users in groups_members.items():
            groupempty = True
            for user in users:
                if user in users_alive:
                    groupempty = False
                elif user in users_dead:
                    users_dead[user].append(group)
                elif self.user_exists(user, dn=True):
                    users_alive.append(user)
                    groupempty = False
                else:
                    users_dead[user].append(group)

            if groupempty:
                groups_dead.append(group)

        if not users_dead and not groups_dead:
            logging.info('Nothing to do.')
            return (0,0)
        print('Will remove users from groups:\n {}\n and will remove groups: \n {}.'.format(dict(users_dead), groups_dead))
        if noninteractive and 'max_user_del_noninteractive' in self.config:
            if len(users_dead) > self.config['max_user_del_noninteractive'] or\
                    len(groups_dead) > self.config['max_user_del_noninteractive']:
                logging.error("Too many entries would be deleted, canceling operation.")
                return False
        else:
            if not yesno('Proceed?', default='y'):
                return False
        for user,groups in users_dead.items():
            for group in groups:
                dn = "cn=%s,ou=Group," % group.decode() + self.config['ldap_realm']
                mod_attrs = [(ldap.MOD_DELETE, 'member', user)]
                if not self.dryrun:
                    self.ldap.modify_s(dn, mod_attrs)
        for group in groups_dead:
            if not self.dryrun:
                self.ldap.delete_s("cn=%s,ou=Group," % group + self.config['ldap_realm'])
        return (users_dead, groups_dead)

class Group():
    def __init__(self, c, group, exists=True):
        self.con    = c
        self.group  = group
        self.attr   = defaultdict(dict)
        self.loaded = False
        self.dn     = "cn=%s,ou=Group," % self.group + self.con.config['ldap_realm']
        if exists:
            self.load()

    def load(self):
        res = self.con.search("ou=Group", "(cn=%s)" % self.group, [])
        if not res:
            logging.error("Group does not exist.")
            self.loaded = False
        elif len(res) > 1:
            logging.error("Group name not unique.")
            self.loaded = False
        else:
            self.attr = dict(map(lambda r: (r[0], r[1][0].decode('utf-8')) if len(r[1]) == 1 else (r[0], [f.decode("utf-8") for f in r[1]]), res[0][1].items()))
            self.loaded = True
            logging.info('Loaded group ' + self.group)
        return self.loaded

    def create(self, users):
        if self.con.group_exists(self.group):
            logging.error("Group already exists.")
            return False
        numgid = str(self.con.get_next_gid()).encode()
        add_record = [
            ('objectclass', [b'groupOfNames', b'posixGroup']),
            ('gidNumber', [numgid]),
            ('cn', [self.group.encode()]),
        ]
        dns = []
        for user in users:
            if self.con.user_exists(user):
                dns.append(("uid=%s,ou=People," % user + self.con.config['ldap_realm']).encode())
            else:
                logging.error('User ' + user + ' does not exist! Wont be added to Group.')
        if len(dns) > 0:
            add_record.append(('member', dns))
            if self.con.dryrun:
                return True
            try:
                self.con.ldap.add_s(self.dn, add_record)
                logging.info('Group %s created.' % self.group)
                self.load()
                return numgid
            except Exception as e:
                logging.error('Group %s was not created: %s' % (self.group, str(e)))
                return False
        else:
            logging.error("Wont create empty group.")
            return False

    def remove(self):
        if not self.loaded:
            return False
        mainusers = self.con.search("ou=People", "(&(objectClass=posixAccount)(gidNumber=%s))" % self.attr['gidNumber'], ['uid'])
        if mainusers:
            logging.error("Can't remove Group. It is the main group of the following users: " + str(mainusers))
            return False
        if self.con.dryrun:
            return True
        try:
            self.con.ldap.delete_s(self.dn)
            self.attr = defaultdict(dict)
            return True
        except Exception as e:
            logging.error('Group %s was not removed: %s' % (self.group, str(e)))
            return False

    def memberedit(self, users, edit):
        if not isinstance(users, list):
            logging.error('A list of users must be given.')
            return False
        member = []
        for user in users:
            if self.con.user_exists(user) or edit == ldap.MOD_DELETE:
                member.append(("uid=%s,ou=People," % user + self.con.config['ldap_realm']).encode('utf-8'))
            else:
                logging.error('User ' + user + ' does not exist!')
        if len(member) == 0:
            return False
        mod_attrs = [(edit, 'member', member)]
        if self.con.dryrun:
            return True
        try:
            if self.con.ldap.modify_s(self.dn, mod_attrs):
                logging.info('Group was modified.')
                self.load()
                return True
            else:
                logging.info('Group was not modified.')
                return False
        except ldap.TYPE_OR_VALUE_EXISTS:
            logging.error('User already part of the group.')
            return False
        except ldap.NO_SUCH_ATTRIBUTE:
            logging.error('User is not part of the group.')
            return False
        except ldap.OBJECT_CLASS_VIOLATION:
            logging.error('Something wen\'t wrong. Is the User the last member of the Group?')
            return False

    def adduser(self, users):
        return self.memberedit(users, ldap.MOD_ADD)

    def deluser(self, users):
        return self.memberedit(users, ldap.MOD_DELETE)

class User():
    def __init__(self, c, user, exists=True):
        self.con    = c
        self.user   = user
        self.loaded = False
        self.attr   = defaultdict(dict)
        self.dn     = "uid=%s,ou=People," % self.user + self.con.config['ldap_realm']
        if exists:
            self.load()

    def load(self):
        if not self.con.user_exists(self.user):
            logging.error('User %s does not exist.' % self.user)
            return False
        self.attr = self.con.get_user_attr(self.user)
        if self.attr:
            if 'gidNumber' in self.attr:
                self.group = self.con.get_group(self.attr['gidNumber']).decode()
            self.loaded = True
            logging.info('Loaded user ' + self.user)
        return self.loaded

    def edit(self, mod_attrs):
        if not self.loaded:
            logging.error('No user loaded.')
            return False
        try:
            if not self.con.dryrun:
                self.con.ldap.modify_s(self.dn, mod_attrs)
                self.load()
        except Exception as e:
            logging.error("Failed to modify user: " + str(e))
            return False
        return True

    def add(self, attr={}):
        if attr:
            self.attr = attr
        else:
            self.attr['uid'] = self.user
            self.attr['gidNumber'] = self.con.get_gid(self.con.config['default_group'])
        if self.con.user_exists(self.attr['uid']):
            logging.error('User %s already exists.' % self.attr['uid'])
            return (False, False)
        if self.user != self.attr['uid']:
            logging.error('"uid" attribute must be set and match the username.')
            return (False, False)

        numuid = self.con.get_next_uid()

        add_record = [
            ('objectclass', ['person', 'organizationalperson', 'inetorgperson',
                             'posixAccount', 'top', 'shadowAccount']),
            ('uid', [str(self.attr['uid'])]),
            ('sn', [str(self.attr['sn'])]),
            ('cn', [str(self.attr['cn'])]),
            ('shadowLastChange', ['0']),
            ('shadowMax', ['800']),
            ('shadowWarning', ['90']),
            ('shadowInactive', ['300']),
            ('loginShell', ['/bin/bash']),
            ('uidNumber', [str(numuid)]),
            ('gidNumber', [self.attr['gidNumber']]),
        ]
        if 'mail' in self.attr and self.attr['mail'] != '':
            add_record += [('mail', [str(self.attr['mail'])])]
        if 'givenName' in self.attr and self.attr['givenName'] != '':
            add_record += [('givenName', [str(self.attr['givenName'])])]
        if 'gecos' in self.attr and self.attr['gecos'] != '':
            add_record += [('gecos', [str(self.attr['gecos'])])]
        if 'homeDirectory' in self.attr and self.attr['homeDirectory'] != '':
            add_record += [('homeDirectory', [str(self.attr['homeDirectory'])])]

        # convert all entries to bytes
        add_record = [ (k, [v.encode('utf-8') if type(v) == str else v for v in vs]) for k,vs in add_record]

        try:
            if not self.con.dryrun:
                self.con.ldap.add_s(self.dn, add_record)
                self.load()
                pw = self.setpw()
                return (numuid, pw)
            else:
                return (42, 'dryrunpw')
        except Exception as e:
            logging.error("Failed to add user: " + str(e))
            return (False, False)

    def remove(self):
        if not self.loaded:
            logging.error('No user loaded.')
            return False

        try:
            if not self.con.dryrun:
                self.con.ldap.delete_s(self.dn)
                self.attr = defaultdict(dict)
        except Exception as e:
            logging.error("Failed to remove user: " + str(e))
            return False
        return True

    def setpw(self):
        if not self.loaded:
            logging.error('No user loaded.')
            return False

        pw = gen_pw()
        try:
            if not self.con.dryrun:
                self.con.ldap.passwd_s(self.dn, None, pw)
            return pw
        except Exception as e:
            logging.error("Failed to change password: " + str(e))
            return False
        return True

    def change_email(self, mail):
        if not self.loaded:
            logging.error('No user loaded.')
            return False

        if '@' not in parseaddr(mail)[1]:
            raise Exception('invalid email address')

        # check if mail is already used
        res = self.con.search('ou=People', "(mail=%s)" % mail, ['mail','uid'])
        if res and len(res) > 0:
            logging.error('The email "{}" is already used by the user "{}".'.format(
                mail, res[0][1]['uid'][0])
                )
            if not yesno("Change anyway?", default="n"):
                return False

        if not self.attr['mail']:
            oldmail = "none"
            logging.error("Seems like the user didn't had a mail before.")
            if not yesno("Set anyway?", default="n"):
                return False
        else:
            oldmail = self.attr['mail']

        # change mail
        logging.info('Changing email: {}:{} -> {}:{}'.format(
            self.user, oldmail, self.user, mail)
            )
        mod_attrs = [(ldap.MOD_REPLACE, 'mail', mail.encode('utf-8'))]
        return self.edit(mod_attrs)

# helper functions outside of connection class
def yesno(question, default='n'):
    alternative = 'y' if not strtobool(default) else 'n'
    bracket = " [{}/{}] ".format(default.upper(), alternative)
    try:
        answer = input(question + bracket) or default
        try:
            boolish = strtobool(answer)
        except ValueError:
            logging.error("Invalid answer! Try again:")
            boolish = yesno(question, default)
        return boolish
    except KeyboardInterrupt:
        print('\nAborting...')
        sys.exit(1)

def pwhashfrompassword(password):
    # crypt uses strongest method available by default
    # in python 3:
    # pwhash = crypt.crypt(password)

    salt = os.urandom(8)  # edit the length as you see fit
    pwhash = '{SSHA}' \
        + base64.b64encode(hashlib.sha1(password + salt).digest() + salt)
    return pwhash

def gen_pw():
    words = xp.locate_wordfile()
    mywords = xp.generate_wordlist(wordfile=words, min_length=5, max_length=8)
    raw_password = xp.generate_xkcdpassword(mywords, numwords=3, delimiter=' ')
    return raw_password

""" python-gnupg still has problems with python3
def get_admin_pw(gpgfile,passphrase=None):
    gpg = GPG(use_agent=True)
    with open(gpgfile, 'rb') as f:
        pw = gpg.decrypt_file(f, passphrase=passphrase)
    if pw.ok:
        print(str(pw).strip())
        return str(pw).strip()
    else:
        logging.error("Failed to encrypt password file!\n" + pw.stderr)
        sys.exit(1)
"""
def get_admin_pw(gpgfile, passphrase=None):
    cmd = ['gpg', '-q', '-d', gpgfile]
    if passphrase:
        cmd.append('--passphrase')
        cmd.append(passphrase)
    proc = Popen(cmd, stderr=STDOUT, stdout=PIPE)
    pipes = proc.communicate(timeout=2)
    stdout = pipes[0].decode('utf8').strip() if pipes[0] else ""
    stderr = pipes[1].decode('utf8').strip() if pipes[1] else ""
    rc = proc.poll()
    if rc != 0:
        logging.error("Failed to encrypt password file!\n" + stderr + "\n" + stdout)
        sys.exit(1)
    return stdout

def addtolist(email, mailinglist):
    return sympa_helper(email, mailinglist, "ADD")

def delfromlist(email, mailinglist):
    return sympa_helper(email, mailinglist, "DELETE")

def sympa_helper(email, mailinglist, command):
    try:
        host = mailinglist['host']
        admin = mailinglist['admin']
        listname = mailinglist['list']
    except KeyError:
        logging.error('Mailinglist not properly configured (need to specify "host","admin" and "list")!')
        return False
    if command not in ['ADD','DELETE']:
        logging.error('Unkown command.')
        return False
    body = "{CMD} {LIST} {MAIL}".format(CMD=command, LIST=listname, MAIL=email)
    mailsend(admin, host, listname, body)
    return True

"""
connect to a gitlab instance
key can be plain text or url to a gpg key
"""
def gitlab_connection(url,key):
    try:
        if str(key).split('.')[-1] == 'gpg':
            api_key = get_admin_pw(key)
        else:
            api_key = key
    except:
        print("Failed to get the GitLab API key from gpg. Make sure gpg is setup accordingly.")
        return False
    gl = gitlab.Gitlab(url, api_key)
    try:
        gl.auth()
    except gitlab.exceptions.GitlabAuthenticationError:
        print("Authentification against GitLab failed")
        return False
    return gl

def log(logfile, summary=""):
    logdir = os.path.dirname(logfile)
    if not os.path.exists(logdir):
            os.makedirs(logdir)
    with open(logfile, 'a') as f:
        log = "{}: SSHCLIENT: {} LOGIN: {} ACTION: {}\n".format(
                datetime.now().strftime('%c'),
                os.environ['SSH_CLIENT'] if 'SSH_CLIENT' in os.environ else 'local',
                os.getlogin(),
                summary)
        f.write(log)

def mailsend(fr, to, sbj, msg, host='localhost'):
    smtp = smtplib.SMTP()
    try:
        smtp.connect(host)
    except Exception as e:
        logging.error('Could not connect to SMTP server: ' + str(e))
    if not isinstance(to, list):
        to = [to]
    msg = """\
From: %s
To: %s
Subject: %s

%s
""" % (fr, ", ".join(to), sbj, msg)
    try:
        smtp.sendmail(fr, to, msg)
    except smtplib.SMTPException as e:
        logging.error("Failed to send email: " + str(e))
    smtp.close()
