#!/usr/bin/python -u
#
# The GIT importer chase the commits done on the main trunk of
# the git SCM used for the project
#
# Note the program does not try to update the git tree itself
# it will use whatever is the state in the given checkout in
# config [git] tree value
#
#

import libxml2
import sys
import os
import time
import string
import subprocess

import config

#
# commit database indexed by commit id
#
commitsdb = {}
authorsdb = {}
emailsdb = {}

def add_commitdb(uuid, author, subject, email, date):
    if commitsdb.has_key(uuid):
        return 0
    commit={}
    commit['subject'] = subject
    commit['author'] = author
    commit['email'] = email
    commit['date'] = date
    commitsdb[uuid] = commit
    if authorsdb.has_key(author):
        patch_list = authorsdb[author]
        patch_list.append(uuid)
    else:
        authorsdb[author] = [uuid]
    if emailsdb.has_key(email):
        patch_list = emailsdb[email]
        patch_list.append(uuid)
    else:
        emailsdb[email] = [uuid]
    return 1

#
# We are not interested in libxml2 parsing errors here
#
def callback(ctx, str):
    return
libxml2.registerErrorHandler(callback, None)

def escape(raw):
    raw = string.replace(raw, '&', '&amp;')
    raw = string.replace(raw, '<', '&lt;')
    raw = string.replace(raw, '>', '&gt;')
    raw = string.replace(raw, "'", '&apos;')
    raw = string.replace(raw, '"', '&quot;')
    return raw

#
# Loading and saving the commit database
#

def save_commit(f, uuid):
    commit = commitsdb[uuid]
    f.write("  <commit id='%s' author='%s' email='%s' date='%s'>\n" % (
            uuid, escape(commit['author']), escape(commit['email']),
            escape(commit['date'])))
    f.write("    <subject>%s</subject>\n" % (escape(commit['subject'])))
    f.write("  </commit>\n")


def save_commits(filename):
    try:
        f = open(filename, 'w')
    except:
        print "Failed to open %s for writing" % filename
        return 0
    f.write("<commits>\n")
    # order by commit date
    k = commitsdb.keys()
    l = sorted(k, key=lambda x: commitsdb[x]['date'])
    n = 0
    for commit in l:
        save_commit(f, commit)
        n += 1
    f.write("</commits>\n")
    print "Saved %d commits to %s\n" % (n, filename)

def load_one_commit(commit):
    try:
        uuid = commit.prop("id")
        author= commit.prop("author")
        email= commit.prop("email")
        date= commit.prop("date")
        subject=commit.xpathEval("string(subject)")
    except:
        print "Failed to load one message from the database", sys.exc_info()
        return 0
    return add_commitdb(uuid, author, subject, email, date)

def load_commits(filename):
    try:
        doc = libxml2.parseFile(filename)
    except:
        print "Failed to read and parse %s" % filename
        return 0
    nb_commits = 0
    ctxt = doc.xpathNewContext()
    commits = ctxt.xpathEval("//commit")
    for commit in commits:
        nb_commits += load_one_commit(commit)
    doc.freeDoc()
    print "loaded %d commits from %s" % (nb_commits, filename)

#
# Growing the commit database
#

def convert_date(raw):
    # convert dates to use same format as indexer
    try:
        l = raw.split()
        last = l[-1]
        if last[0] == '-' or last[0] == '+':
            l = l[:-1]
        raw = string.join(l)
        t = time.strptime(raw, "%Y-%m-%d %H:%M:%S")
        raw = time.strftime("%Y%m%d %H:%M:%S", t)
    except:
        print "Failed to scan date %s" % (raw)
    return raw

#
# this function runs the command to fetch the commit logs
#
def split_commit_line(line):
    cur = line.find("commit_id=")
    if cur < 0:
        return None
    nxt = line.find(" commit_subject=")
    if nxt < cur:
        return None
    uuid = line[cur+10:nxt]
    cur = nxt
    nxt = line.find(" commit_author=")
    if nxt < cur:
        return None
    subject = line[cur+16:nxt]
    cur = nxt
    nxt = line.find(" commit_email=")
    if nxt < cur:
        return None
    author = line[cur+15:nxt]
    cur = nxt
    nxt = line.find(" commit_date=")
    if nxt < cur:
        return None
    email = line[cur+14:nxt]
    cur = nxt
    nxt = line.find(" commit_end=")
    if nxt < cur:
        return None
    date = convert_date(line[cur+13:nxt])

    return (uuid, subject, author, email, date)

def refresh_one_commit(line):
    try:
        (uuid, subject, author, email, date) = split_commit_line(line)
    except:
        print "Failed to parse one git log line output"
        return 0
    if commitsdb.has_key(uuid):
        return 0

    return add_commitdb(uuid, author, subject, email, date)

def refresh_commit_logs(tree, size):
    if tree == None:
        return -1
    if size < 100:
        size = 100
    nb_commits = 0

    log_format = """commit_id=%H commit_subject=%s commit_author=%an commit_email=%ae commit_date=%ci commit_end="""

    args = ["git", "--git-dir=%s" % (tree), "log", "--max-count=%s" % (size),
                 "--pretty=format:\"%s\"" % (log_format) ]
    try:
        pipe = subprocess.Popen(args, stdout=subprocess.PIPE).stdout
    except:
        print "Failed to update the commit log file", sys.exc_info()
        return -1

    for line in pipe:
        nb_commits += refresh_one_commit(line)

    return nb_commits

def get_git_tree_directory():
    git_tree = config.get_git_tree()
    if not os.path.isdir(git_tree):
        print "git tree %s should be a directory" % git_tree
        return None
    if os.path.isdir(git_tree + "/.git"):
        return git_tree + "/.git"
    return git_tree

def initialize():
    load_commits(config.get_git_dbname())

    git_db = get_git_tree_directory()
    ret = refresh_commit_logs(git_db, config.get_git_logsize())
    print "loaded %d new commits from %s" % (ret, config.get_git_tree())

#
# Strict lookup for exact patch informations
#
def lookup_patch(subject, author, email):
    for c in commitsdb.keys():
        commit = commitsdb[c]
        if (author == commit['author'] or email == commit['email']) and \
            subject == commit['subject']:
            return c
    return ""

def get_commit_date(uuid):
    try:
        return commitsdb['uuid']['date']
    except:
        return ""

def save():
    save_commits(config.get_git_dbname())

def statistics():
    print "%d email for %d authors found" % (len(emailsdb), len(authorsdb))

def main():
    initialize()
    statistics()
    save()



if __name__ == "__main__":
    main()
