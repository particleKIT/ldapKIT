# LDAP User Script Toolkit

A collection of python scripts that act as a wrapper/cli for the python-ldap library. There is an overall config file config.yml. The scripts have the following functionalities:

  * add/delete LDAP accounts,
  * create/archive user directories (and set quotas) belonging to these accounts on all fileservers according to the settings in the config.yml,
  * change email addresses in LDAP, GitLab and mailing list subscriptions
  * reset passwords
  * create/remove groups in ldap
  * add/remove users from LDAP groups

All scripts provide ``--help``, ``--verbose`` and ``--dryrun`` flags.

# Install
```
pip install ldapKIT
```

# User add/delete

To add/delete users, you can use the scripts: ``particleldapuseradd`` and ``particleldapuserdel -–user NAME``.  
There is also the functionality to search for users that are inactive for ``n`` days (inactive means: last password change older than  ``m`` days) and delete them with ``particleldapuserdel –-cleanup``.  
The userdel script does not only remove the ldap user but is also able to run post-deletion tasks via ansible e.g. to backup user directories.
  
# Group add/delete/modify

This is done via the tool ``particleldapgroup``. Usage:
```bash
# particleldapgroup --help
usage: particleldapgroup [-h] [--verbose] [--dryrun]
                         {create,delete,adduser,deluser,cleanup} ...

positional arguments:
  {create,delete,adduser,deluser,cleanup}
    create              create new group
    delete              delete group
    adduser             add users to group
    deluser             remove users from group
    cleanup             remove non-existant users from group

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         add more ouput
  --dryrun, -d          don't write anything
```


# Changing E-Mail Addresses

There is the script ``particleldapchangeemail`` which changes the email of an user in its:

  * LDAP account,
  * GitLab account (which somehow does not update its database when an ldap account changes its email)
  * and removes/adds its old/new email to a configured mailing list.

# Example configuration
See the [config.yml](./example/config.yml) for an example configuration which uses the full functionality. Also see the [userdir.yml](./example/userdir.yml) which is an ansible playbook invoked by ``particleldapuser{add,del}`` to create/archive user dirs on foregin file servers (set in the config.yml).
