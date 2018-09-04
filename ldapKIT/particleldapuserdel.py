#!/usr/bin/env python3
import sys
import logging
import argparse
from subprocess import check_call, CalledProcessError
from distutils.spawn import find_executable
from time import time

from . import ldapKIT

def remove_user(c,args):
    log = 'USERDELETE ' + args.user + ': '
    rc = 0
    user = ldapKIT.User(c,args.user, exists=True)
    if not user.loaded:
        return 1

    # users email/group
    email = user.attr['mail'] if 'mail' in user.attr else ''
    group = user.group

    # remove ldap account and clean up afterwards
    if (args.noninteractive or ldapKIT.yesno('Remove ldap account %s?' % args.user, default='y')) and not args.dryrun:
        log += 'Removed %s from ldap' % args.user
        if user.remove():
            log += '.'
            print('OK')
            print('Clearing old LDAP entries...')
            c.remove_dead_entries(noninteractive=args.noninteractive)
        else:
            print('Skipping dir deletion for safety reasons.')
            log += ' (failed).'
            rc = 1

    # check if group is configured
    try:
        dirs = c.config['user_main_groups'][group]['machine_dir_map']
    except KeyError:
        print('Skipping deletion of user dirs (not configured).')
    try:
        mailinglist = c.config['user_main_groups'][group]['mailinglist']
    except KeyError:
        print('Skipping deletion of mailling list membership (not configured).')

    # remove email from mailling list
    if not args.keepemail and email and mailinglist and\
            (args.noninteractive or ldapKIT.yesno('Remove {} from email list {}?'.format(email, mailinglist['list']), default='y')):
        if not args.dryrun:
            log += ' Removed from email list' + mailinglist['list']
            if ldapKIT.delfromlist(email, mailinglist):
                print('OK')
                log += '.'
            else:
                log += ' (failed).'
                rc = 1

    # backup/delete user dirs
    if not args.keepdirs and dirs and rc == 0 and\
            (args.noninteractive or ldapKIT.yesno('Backup and remove %ss dirs?' % args.user, default='y')):
        if 'ansible' not in c.config or \
                'userdir_delete' not in c.config['ansible'] or\
                'playbook' not in c.config['ansible']['userdir_delete']:
            logging.error('Ansible not configured for userdir deletion')
            log += 'Ansible was not cofigured.'
            rc = 1

        ansible_exec = find_executable('ansible-playbook')
        if not ansible_exec:
            logging.error('Ansible not installed (could not find ansible-playbook executable).')
            rc = 1

        ansiblecmd = [ansible_exec, c.config['ansible']['userdir_delete']['playbook']]
        ansiblecmd.append('-e username="%s"' % args.user)
        if 'extra_args' in c.config['ansible']['userdir_delete']:
            ansiblecmd.extend(c.config['ansible']['userdir_delete']['extra_args'])

        if args.dryrun:
            ansiblecmd.append('--check')
            print('Spawning Ansible with --check.')
        if args.verbose > 1:
            ansiblecmd.append('--vvv')
        if args.noninteractive:
            ansiblecmd.append('-e noninteractive=True')

        ansiblecmd.append('-e uid=' + args.user)
        ansiblecmd.append('-e gid=' + group)

        i = 0
        for dirinfo in dirs:
            ansibledir_arg = ['-e dir=' + str(i), '-i' + dirinfo['host'] + ',']
            i += 1
            logging.info('calling ' + ' '.join(ansiblecmd + ansibledir_arg))
            try:
                check_call(ansiblecmd + ansibledir_arg)
                check_call(['true'])
            except CalledProcessError:
                logging.error('Ansible failed. Try running the playbook manually.')
                log += 'failed to delete %s.' % dirinfo['dir']
                rc = 1

        log += 'Dirs deleted.'

    ldapKIT.log(c.config['logdir'] + '/userdel.log', log)
    return rc

def cleanup_users(c, args):
    shadows = c.search("ou=People", "(objectClass=posixAccount)", ['uid', 'shadowLastChange'])
    if 'inactive_after_shadowLastChange_days' not in c.config:
        logging.error('Config variable "inactive_after_shadowLastChange_days" must be set to determine inactive users.')
        return 1
    else:
        now = int(time()/86400)
        deltamax = int(c.config['inactive_after_shadowLastChange_days'])

    users_inactive = []
    for user in shadows:
        if 'shadowLastChange' in user[1]:
            shadow = int(user[1]['shadowLastChange'][0])
            if shadow == 0 or now - shadow <= deltamax:
                continue
            users_inactive.append(str(user[1]['uid'][0]))

    if not users_inactive:
        print('No inactive users found.')
        return 0

    print('Found inactive user(s): ' + ', '.join(users_inactive))
    if not args.noninteractive and not ldapKIT.yesno('Do you want to delete them?', default='n'):
        return 0
    if args.noninteractive and 'max_user_del_noninteractive' in c.config and\
            c.config['max_user_del_noninteractive'] <= len(users_inactive):
        logging.error('To many users to delete noninteractively. Please run without --noninteractive.')
        return 1

    users_success = []
    for user in users_inactive:
        args.user = user
        print('Removing user ' + user)
        if remove_user(c,args) == 0:
            users_success.append(user)
    users_failed = list(set(users_inactive) - set(users_success))
    if users_success:
        print('User(s): %s successfully removed.' % ', '.join(users_success))
    if users_failed:
        logging.error('Something went wrong while removing the user(s) ' + ', '.join(users_failed))
        return 1
    return 0

def run():
    parser = argparse.ArgumentParser()
    parser_group = parser.add_mutually_exclusive_group(required=True)
    parser_group.add_argument('--user', '-u',
                        help='username of single user to delete')
    parser_group.add_argument('--cleanup', '-c',
                        help='delete all inactive users', action='store_true')
    parser.add_argument('--keepemail', '-e', action='store_true',
                        help='don\'t remove from mailinglist')
    parser.add_argument('--keepdirs', '-d', action='store_true',
                        help='don\'t remove its directories')
    parser.add_argument('--noninteractive', '-n', action='store_true',
                        help='run non-interactively, don\'t ask questions')
    parser.add_argument('--dryrun', action='store_true',
                        help='don\'t change anything.')
    parser.add_argument('--verbose', '-v', action='count',
                        help='verbosity level',
                        default=0)
    args = parser.parse_args()

    if args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.dryrun:
        print('Dry run enabled.')

    c = ldapKIT.Connection(dryrun=args.dryrun)

    if args.user:
        rc = remove_user(c, args)
    elif args.cleanup:
        rc = cleanup_users(c, args)
    sys.exit(rc)
