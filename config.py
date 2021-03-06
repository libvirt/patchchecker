#!/usr/bin/python -u
#
# module to access the configuration values in the
# patchchecker config file
#

import ConfigParser
import sys
import os
import time

config = ConfigParser.ConfigParser()

#
# Two mandatory settings:
#
#
# Path to the git checkout, preferably an absolute path
# There is no default
#
def get_git_tree():
    return config.get("git", "tree")

def get_mail_archives():
    return config.get("mail", "archives")

#
# Various optional settings
#

#
# Commit log size to extract, 500 is the default
#
def get_git_logsize():
    try:
        return config.getint("git", "logsize")
    except:
        return 500

#
# Maximum number of mails archives pages to fetch in a single pass default 100
#
def get_mail_max_fetch():
    try:
        return config.getint("mail", "archives")
    except:
        return 100

#
# Numbers of days without feedback on a patch before reporting it default 5
#
def get_patch_maxlag():
    try:
        return config.getint("patches", "maxlag")
    except:
        return 5

#
# Don't report messages older than X days. 0 to turn off. Default 0
def get_patch_cutoff():
    try:
        return config.getint("patches", "cutoff")
    except:
        return 0

#
# Do not report patches matching the regexp
def get_patch_excludes():
    return config.get("patches", "excludes")

#
# Filename for the XML database for commits, default is commits.xml
#
def get_git_dbname():
    try:
        return config.get("git", "dbname")
    except:
        return "commits.xml"

#
# Filename for the XML database for messages, default is messages.xml
#
def get_mail_dbname():
    try:
        return config.get("mail", "dbname")
    except:
        return "messages.xml"

#
# Filename for the XML database for patches, default is patches.xml
#
def get_patches_dbname():
    try:
        return config.get("patches", "dbname")
    except:
        return "patches.xml"

def check():
    # verify that the 2 defaults are there
    # and that dbnames don't cponflict
    get_git_tree()
    get_mail_archives()

    if get_patches_dbname() == get_mail_dbname():
        print "dbnames for patches and mail conflicts !"
        sys.exit(1)

    if get_patches_dbname() == get_git_dbname():
        print "dbnames for patches and git conflicts !"
        sys.exit(1)

    if get_mail_dbname() == get_git_dbname():
        print "dbnames for mail and git conflicts !"
        sys.exit(1)


def initialize(filename = ""):
    if filename == "":
        if os.path.exists("patchchecker.conf"):
            filename = "patchchecker.conf"
        else:
            filename = os.getenv("HOME") + "/.patchchecker"
            if not os.path.exists(filename):
                print "Missing config file patchchecker.conf or ~/.patchchecker"
                sys.exit(1)
    try:
        config.read(filename)
    except:
        print "Failed to parse configuration file %s", sys.exc_info()
        sys.exit(1)
    check()

initialize()

#
# if we have a cutoff on report then we can avoid processing
# patches, messages and commit older than the cutoff. Add a
# one month margin to avoid dropping mails which could still
# be relevant (mail threads are unlikely to last more than a month)
#
current_date = time.time()
try:
    cutoff_date = get_patch_cutoff()
    cutoff_date += 30                 # Add a month
    cutoff_date *= (24 * 60 * 60)     # Convert to seconds
except:
    cutoff_date = 0

def outdated(date):
    global cutoff_date
    global current_date

    if cutoff_date == 0:
        return 0

    try:
        t = time.mktime(time.strptime(date, "%Y%m%d %H:%M:%S"))
        if current_date - t > cutoff_date:
            return 1
    except:
        return 0
    return 0

def main():
    print "Configured for git tree %s" % (get_git_tree())
    print "Using archive %s" % (get_mail_archives())

if __name__ == "__main__":
    main()

