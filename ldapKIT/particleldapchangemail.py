#!/usr/bin/env python3

import argparse
import sys
import logging

from . import ldapKIT

parser = argparse.ArgumentParser(description='change users email')

parser.add_argument('--user',
                    '-u',
                    required=True,
                    help='name of the useraccount')

parser.add_argument('--mail',
                    '-m',
                    required=True,
                    help='new mail address to set')

parser.add_argument('--dryrun',
                    '-d',
                    action='store_true',
                    help='don\'t write anything, print old and new mail')

parser.add_argument('--verbose', '-v', action='count',
                    help='add more ouput',
                    default=0)

def run():
    args = parser.parse_args()
    if args.dryrun:
        print("dryrun is enabled")

    c = ldapKIT.Connection(dryrun=args.dryrun)
    user = ldapKIT.User(c, args.user)

    logfile = c.config['logdir'] + '/changemail.log'

    logging.getLogger().setLevel(logging.ERROR)
    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.INFO)

    # get users mail
    try:
        mailinglist = c.config['user_main_groups'][user.group]['mailinglist']
    except KeyError:
        logging.error('No mailinglist for group %s configured!' % user.group)
        sys.exit(0)

    if user.attr['mail']:
        oldmail = user.attr['mail']
        print("user {} has mail {}.".format(args.user,oldmail))
    else:
        print("Could not find any old email for user " + args.user)
        oldmail = False

    # change users email
    if not args.dryrun and \
            ldapKIT.yesno("change email {}->{} of user {}?".format(oldmail, args.mail, args.user), default='y') and \
            user.change_email(args.mail):
        print("Mail was changed to %s." % args.mail)
        ldapKIT.log(logfile, "changed mail: {} -> {}".format(oldmail, args.mail))
    else:
        print("Mail was not changed.")

    # remove old mail from mailing list
    if oldmail:
        if ldapKIT.yesno("remove old email {} from {} mailing list?".format(oldmail, mailinglist['list']),default='y'):
            if args.dryrun:
                print('dry run enabled')
            else:
                ldapKIT.delfromlist(oldmail, mailinglist)
                ldapKIT.log(logfile, "removed {} from list {}".format(oldmail, mailinglist['list']))

        if ldapKIT.yesno("add new email {} to {} mailing list?".format(args.mail, mailinglist['list']), default='y'):
            if args.dryrun:
                print('dry run enabled')
            else:
                ldapKIT.addtolist(args.mail, mailinglist)
                ldapKIT.log(logfile, "added {} to list {}".format(args.mail, mailinglist['list']))

    if 'gitlab_url' in c.config and ldapKIT.yesno("Change mail of %ss GitLab account?" % args.user, default='y'):
        gl = ldapKIT.gitlab_connection(c.config['gitlab_url'], c.config['gitlab_api_token'])
        if not gl:
            sys.exit(1)
        gitlab_user = False
        gitlab_users = gl.users.list(username=args.user)
        if len(gitlab_users) == 0:
            print("no GitLab account with username '%s' found. Please change manually." % args.user)
        elif len(gitlab_users) > 1:
            print("multiple GitLab account found: ")
            i = 0
            for user in gitlab_users:
                print("id: {} user: {} mail: {}".format(i, user.username, user.email))
                i = i + 1
            print("choose on of the above ids: ")
            i = raw_input()
            gitlab_user = gitlab_users[i]
        else:
            gitlab_user = gitlab_users[0]
        if gitlab_user:
            try:
                gitlab_user.email = args.mail
                if not args.dryrun:
                    gitlab_user.save()
                    ldapKIT.log(logfile, "changed gitlab mail {} to {}".format(oldmail, args.mail))
                else:
                    print("dry run enabled")
            except Exception as e:
                print("An error occured: " + str(e))

    print("done.")
