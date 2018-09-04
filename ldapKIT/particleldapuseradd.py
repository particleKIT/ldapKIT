#!/usr/bin/env python3
import argparse
import re
import logging
from subprocess import check_call, CalledProcessError
from distutils.spawn import find_executable
import sys

from . import ldapKIT

parser = argparse.ArgumentParser(description="Add user to Ldap and Infrastructure.")
parser.add_argument('--user', '-u',
                    help='user name')
parser.add_argument('--group', '-g',
                    help='main group of new user')
parser.add_argument('--mail', '-m',
                    help='email address of new user')
parser.add_argument('--first', '-F',
                    help='first name')
parser.add_argument('--last', '-S',
                    help='last name')
parser.add_argument('--comment', '-c',
                    help='Additional Information, like room/phone')
parser.add_argument('--groups', '-G',
                    help='additional groups of new user')
parser.add_argument('--dryrun', '-d',
                    action='store_true',
                    help='Don\'t write anything.')
parser.add_argument('--verbose', '-v', action='count',
                    help='verbosity level',
                    default=0)
args = parser.parse_args()

if args.verbose == 1:
    logging.getLogger().setLevel(logging.INFO)
elif args.verbose >= 2:
    logging.getLogger().setLevel(logging.DEBUG)

ldapcon = ldapKIT.Connection(dryrun=args.dryrun)

logfile = ldapcon.config['logdir'] + '/useradd.log'

"""
Helper functions
"""
def ask_input(question,
              defaultval=None,
              choices=None,
              format=None,
              formathint="Your input format was incorrect",
              check_func=None
              ):
    while True:
        if defaultval is None:
            sys.stdout.write(question)
        else:
            sys.stdout.write(question + " [%s] " % defaultval)
        try:
            userinput = input()
        except KeyboardInterrupt:
            print('\naborting...')
            sys.exit(1)
        if defaultval is not None and userinput.strip() == '':
            return defaultval
        if choices is not None:
            if userinput in choices:
                return userinput
            matches = [c for c in choices if c.startswith(userinput)]
            if len(matches) == 1:
                return matches[0]
            print("Please enter one of %s" % choices)
            continue
        if format is not None:
            match = re.match(format, userinput)
            if match:
                return userinput
            else:
                print(formathint)
        elif check_func is not None:
            try:
                check_func(userinput)
            except Exception as exc:
                print(exc)
                continue
            else:
                return userinput
        else:
            # always accept input if neither format nor check_func is given
            return userinput

def check_username(user):
    pattern = re.compile(r'^[a-z][a-z0-9_-]*$')
    if not pattern.match(user):
        raise Exception('username has forbidden characters')
    if len(user) > 30:
        raise Exception('username is too long')
    if ldapcon.user_exists(user):
        raise Exception('username already exists')
    # check if user already exists in gitlab
    if 'gitlab_url' not in ldapcon.config:
        return True
    gitlabcon = ldapKIT.gitlab_connection(ldapcon.config['gitlab_url'], ldapcon.config['gitlab_api_token'])
    if not gitlabcon:
        raise Exception('username could not be compared with gitlab database')
    gitlab_users = gitlabcon.users.list(username=user)
    if len(gitlab_users) > 0:
        logging.error("seems like the username already exists in our gitlab instance (non-ldap user):")
        for user in gitlab_users:
            logging.error(user.username)
        raise Exception("username already exists in GitLab")

def check_groups(groups):
    for group in groups.split(','):
        if group != '' and not ldapcon.group_exists(group):
            raise Exception('Group %s does not exist' % group)

def run():
    """
    ask for user input and check it
    """
    attr = {}
    attr['uid'] = ask_input("login name: ", check_func=check_username) if not args.user else args.user
    group = ask_input("select main group '" + ', '.join(list(ldapcon.config['user_main_groups'])) + '": ' , choices=list(ldapcon.config['user_main_groups'])) if not args.group else args.group
    attr['homeDirectory'] = ldapcon.config['user_main_groups'][group]['home'].replace('{{uid}}', attr['uid'])
    attr['gidNumber'] = ldapcon.get_gid(group)
    attr['mail'] = ask_input("email: ", format="[^@]+@[^@]+\.[^@]+") if not args.mail else args.mail
    attr['givenName'] = ask_input("first name: ") if not args.first else args.first
    attr['sn'] = ask_input("last name: ", format="^[a-zA-Z ,.'-]+$") if not args.last else args.last
    attr['cn'] = '{} {}'.format(attr['sn'], attr['givenName'])
    attr['gecos'] = ",".join(filter(None, [attr['cn'], ask_input("room: "), ask_input("phone: ")])) if not args.comment else args.comment
    groups = ask_input(
            "additional groups\ncomma seperated, no blanks\nyou probably should add ssh: ",
            check_func=check_groups,
            ) if not args.groups else args.groups
    """
    print the input and ask for confirmation
    """
    print("login name: %s" % attr['uid'])
    print("group: %s" % group)
    print("mail: %s" % attr['mail'])
    print("name: %s %s" % (attr['sn'], attr['givenName']))
    print("comment: %s" % attr['gecos'])
    print("other groups: %s" % groups)
    print("to reproduce run: particleldapuseradd --user=%s --group=%s" % (attr['uid'], group) +
          " --mail=%s --first=%s --last=%s" % (attr['mail'], attr['givenName'], attr['sn']) +
          " --comment=%s --groups=%s" % (attr['gecos'], groups)
          )
    if not ldapKIT.yesno("Is this correct?", default="y"):
        print("exiting...")
        sys.exit(0)

    """
    add user to infrastructure: ldap, mailing lists, user dirs
    """
    print('Adding user %s to Ldap:' % attr['uid'])
    user = ldapKIT.User(ldapcon, attr['uid'], exists=False)
    userid, userpw = user.add(attr)
    if not userid or not userpw:
        sys.exit(1)
    print('User id: ' + str(userid))
    print('Your pw is: "%s" (without quotes, including spaces). Please change immediately!' % userpw)

    if groups and not args.dryrun:
        print('Adding user %s to groups: %s.' % (attr['uid'], groups))
        for g in groups.split(','):
            ldapKIT.Group(ldapcon, g, exists=True).adduser([attr['uid']])

    try:
        mailinglist = ldapcon.config['user_main_groups'][group]['mailinglist']
    except KeyError:
        print('Skipping creation of mailling list membership (not configured).')

    if attr['mail'] and 'email_welcome_text' in ldapcon.config and not args.dryrun:
        welcome_mail = ldapcon.config['email_welcome_text'].replace('{{group}}', group)
        for k,v in attr.items():
            welcome_mail = welcome_mail.replace('{{%s}}' % str(k), str(v))
        ldapKIT.mailsend(
                ldapcon.config['email_from'],
                attr['mail'],
                ldapcon.config['email_welcome_subject'],
                welcome_mail,
                ldapcon.config['email_smtp_host']
                )

    if attr['mail'] and mailinglist and ldapKIT.yesno('Adding user %s to email list %s ?' % (attr['uid'], group), default='y'):
        if not args.dryrun:
            ldapKIT.addtolist(attr['mail'], mailinglist)
        else:
            print('(dryrun enabled)')

    if 'ansible' not in ldapcon.config or \
            'userdir_create' not in ldapcon.config['ansible'] or\
            'playbook' not in ldapcon.config['ansible']['userdir_create']:
        logging.error('Ansible not configured for userdir creation')
        sys.exit(1)

    ansible_exec = find_executable('ansible-playbook')
    if not ansible_exec:
        logging.error('Ansible not installed (could not find ansible-playbook executable).')
        sys.exit(1)

    ansiblecmd = [ansible_exec, ldapcon.config['ansible']['userdir_create']['playbook']]
    if 'extra_args' in ldapcon.config['ansible']['userdir_create']:
        ansiblecmd.extend(ldapcon.config['ansible']['userdir_create']['extra_args'])

    if args.dryrun:
        ansiblecmd.append('--check')
        print('Spawning Ansible with --check.')

    if args.verbose > 1:
        ansiblecmd.append('-vvv')

    ansiblecmd.append('-e uid=' + attr['uid'])
    ansiblecmd.append('-e gid=' + group)

    i = 0
    for dirinfo in ldapcon.config['user_main_groups'][group]['machine_dir_map']:
        ansibledir_arg = ['-e dir=' + str(i), '-i' + dirinfo['host'] + ',']
        i += 1
        if not ldapKIT.yesno("Create dir '%s' on %s?" % (dirinfo['dir'].replace('{{uid}}',attr['uid']), dirinfo['host']) , default="y"):
            continue
        logging.info('calling ' + ' '.join(ansiblecmd + ansibledir_arg))
        try:
            check_call(ansiblecmd + ansibledir_arg)
        except CalledProcessError:
            logging.error('Ansible failed. Try running the playbook manually.')

    ldapKIT.log(logfile, "add user: " + attr['uid'])
