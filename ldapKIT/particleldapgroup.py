#!/usr/bin/env python3

import argparse
import logging

from . import ldapKIT

def parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd')
    create = subparsers.add_parser('create', help='create new group')
    delete = subparsers.add_parser('delete', help='delete group')
    adduser = subparsers.add_parser('adduser', help='add users to group')
    deluser = subparsers.add_parser('deluser', help='remove users from group')
    subparsers.add_parser('cleanup', help='remove non-existant users from group')

    for p in (create, delete, adduser, deluser):
        p.add_argument('group', help='name of group')

    for p in (create, adduser, deluser):
        p.add_argument('users', nargs='+', help='names of users')

    parser.add_argument('--verbose', '-v', action='count',
                        help='add more ouput')

    parser.add_argument('--dryrun', '-d', action='store_true',
                        help='don\'t write anything',
                        default=0)
    return parser

def run():

    args = parser().parse_args()
    logging.getLogger().setLevel(logging.ERROR)
    if args.verbose and args.verbose >= 1:
        logging.getLogger().setLevel(logging.INFO)
    cmd = args.cmd
    if not cmd:
        parser().parse_args(['--help'])

    c = ldapKIT.Connection(dryrun=args.dryrun)
    log = None
    if args.dryrun:
        print('Dryrun enabled.')

    if cmd == 'create':
        group = ldapKIT.Group(c,args.group, exists=False)
        out = group.create(args.users)
        log = 'group %s created' % args.group
    elif cmd != 'cleanup':
        group = ldapKIT.Group(c,args.group, exists=True)

    if cmd == 'delete':
        out = group.remove()
        log = 'group %s deleted' % args.group
    elif cmd == 'adduser':
        out = group.adduser(args.users)
        log = 'user {} added to group {}'.format(args.users, args.group)
    elif cmd == 'deluser':
        out = group.deluser(args.users)
        log = 'user {} removed from group {}'.format(args.users, args.group)
    elif cmd == 'cleanup':
        out = c.remove_dead_entries()
        log = 'cleaned up groups'

    if log:
        if out:
            print(log)
        else:
            log = log + '(failed)'
            print('An error occured (try running with -v for more output).')
    ldapKIT.log(c.config['logdir'] + '/group.log', log)
