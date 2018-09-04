#!/usr/bin/env python3
import logging
import argparse
from sys import exit

from . import ldapKIT


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('user',
                        help='username to reset password for')
    parser.add_argument('--verbose', '-v', action='count',
                        help='verbosity level',
                        default=0)
    parser.add_argument('--dryrun', '-d', action='store_true',
                        help='don\'t change anything.')
    args = parser.parse_args()

    if args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    return args

def run():
    args = parse_args()

    c = ldapKIT.Connection(dryrun=args.dryrun)
    user = ldapKIT.User(c, args.user, exists=True)

    if not user.loaded:
        exit(1)

    print("Changing password for %s" % args.user)
    pw = user.setpw()
    if pw:
        print("The new password is %s" % pw)
    else:
        print("Password was not changed.")
        exit(1)
