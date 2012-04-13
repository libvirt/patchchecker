#!/usr/bin/python -u
#
# The patch checker program, works out of a mail database saved by
# the indexer. It will look out if there are patches out there
# which were not ACK'ed for example


import libxml2
import shutil
import sys
import string
import os
import re
import difflib
import time
import gitimport

import config

verbose = 0

#
# database handling
#   - messagesdb contains the full set of messages indexed by msgid
#   - patchesdb contains the set of patches and their identified state
#   - refsdb is an inverted reference database indexed by mailid of the referred
#
messagesdb={}
patchesdb={}
refsdb={}
acksdb={}
patchsetsdb={}
authorsdb={}

def merge_list(l1, l2):
    return [i for i in set(l1 + l2)]


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
# Loading and saving the patch database
#

#
def add_patchesdb(mailid, msgid, subject, date,
                  acks = [], reviews = [], commit = None,
                  author = None, email = None, cdate = None,
                  patchset = None, url = None):

    if config.outdated(date):
        return -1

    # we index by mailid
    if patchesdb.has_key(mailid):
        patch = patchesdb[mailid]
        if patch["msgid"] == None or patch["msgid"] == "":
            patch["msgid"] = msgid
        if patch["subject"] == None or patch["subject"] == "":
            patch["subject"] = subject
        if patch["date"] == None or patch["date"] == "":
            patch["date"] = date
        if acks != []:
            patch["acks"] = merge_list(patch["acks"], acks)
        if reviews != []:
            patch["reviews"] = merge_list(patch["reviews"], reviews)
        if patch["commit"] == None:
            patch["commit"] = commit
        if patch["author"] == None:
            patch["author"] = author
        if patch["email"] == None:
            patch["email"] = author
        if patch["cdate"] == None:
            patch["cdate"] = cdate
        if patch["patchset"] == None:
            patch["patchset"] = patchset
        if patch["url"] == None:
            patch["url"] = url
    else:
        patch={}
        patch["msgid"] = msgid
        patch["subject"] = subject
        patch["date"] = date
        patch["acks"] = merge_list(acks, [])
        patch["reviews"] = merge_list(reviews, [])
        patch["commit"] = commit
        patch["author"] = author
        patch["email"] = email
        patch["cdate"] = cdate
        patch["patchset"] = patchset
        patch["url"] = url
        patchesdb[mailid] = patch
        return 1
    return 0

def save_patch(f, uuid):
    patch = patchesdb[uuid]
    f.write("  <patch mailid='%s' msgid='%s' date='%s'" % (
            escape(uuid), patch["msgid"], escape(patch['date'])))
    if patch["author"] != None:
        f.write(" author='%s'" % (escape(patch['author'])))
    if patch["email"] != None:
        f.write(" email='%s'" % (escape(patch['email'])))
    if patch["patchset"] != None:
        f.write(" patchset='%s'" % (escape(patch['patchset'])))
    f.write(">\n")
    f.write("    <subject>%s</subject>\n" % (escape(patch['subject'])))
    if patch["url"] != None and patch["url"] != "":
        f.write("    <url>%s</url>\n" % (escape(patch['url'])))
    if patch["commit"] != None and patch["commit"] != "":
        f.write("    <commit")
        if patch["cdate"] != None:
            f.write(" cdate='%s'" % (escape(patch['cdate'])))
        f.write(">%s</commit>\n" % (escape(patch['commit'])))
    if patch["reviews"] != []:
        for rev in patch["reviews"]:
            f.write("    <review>%s</review>\n" % (escape(rev)))
    if patch["acks"] != []:
        for ack in patch["acks"]:
            f.write("    <ack>%s</ack>\n" % (escape(ack)))
    f.write("  </patch>\n")


def save_patches(filename):
    try:
        f = open(filename, 'w')
    except:
        print "Failed to open %s for writing" % filename
        return 0
    f.write("<patches>\n")
    k = patchesdb.keys()
    l = sorted(k, key=lambda x: patchesdb[x]['date'])
    n = 0
    for patch in l:
        save_patch(f, patch)
        n += 1
    f.write("</patches>\n")
    print "Saved %d patches to %s\n" % (n, filename)

def load_one_patch(patch):
    acks = []
    reviews = []
    try:
        mailid = patch.prop("mailid")
        msgid= patch.prop("msgid")
        date= patch.prop("date")
        subject=patch.xpathEval("string(subject)")
        author= patch.prop("author")
        email= patch.prop("email")
        patchset= patch.prop("patchset")
        commit= patch.xpathEval("string(commit)")
        url= patch.xpathEval("string(url)")
        cdate=patch.xpathEval("string(commit/@cdate)")
        try:
            for rev in patch.xpathEval("review"):
                reviews.append(rev.content)
        except:
            pass
        try:
            for ack in patch.xpathEval("ack"):
                acks.append(ack.content)
        except:
            pass
    except:
        print "Failed to load one message from the database", sys.exc_info()
        return 0
    return add_patchesdb(mailid, msgid, subject, date, acks, reviews,
                         commit, author, email, cdate, patchset, url)

def load_patches(filename):
    try:
        doc = libxml2.parseFile(filename)
    except:
        print "Failed to read and parse %s" % filename
        return 0
    nb_patches = 0
    too_old = 0
    ctxt = doc.xpathNewContext()
    patches = ctxt.xpathEval("//patch")
    for patch in patches:
        ret = load_one_patch(patch)
        if ret == -1:
            too_old += 1
        else:
            nb_patches += ret
    doc.freeDoc()
    print "loaded %d patches from %s, discarded %d old" % (nb_patches,
           filename, too_old)

def add_messagedb(msgid, url = "", author = "", address = "", mailid = "", subject = "", date="", patches=0, ack=0, refs=[]):

    if msgid == None or msgid == "":
        return

    if config.outdated(date):
        return -1

    if mailid == None:
        mailid = ""
    if subject == None:
        subject = ""
    if author == None:
        author = ""
    if address == None:
        address = ""
    if url == None:
        url = ""
    if refs == None:
        refs = []

    #
    # We are really using the mail id to index everything as it's the
    # identifier allowing to build the cross references
    # it's a difference from similar code in the indexer
    #
    if mailid == "":
        mailid = msgid

    try:
        msg = messagesdb[mailid]
        if msgid != "":
            msg["msgid"] = msgid
        if url != "":
            msg["url"] = url
        if subject != "":
            msg["subject"] = subject
        if author != "":
            msg["author"] = author
        if address != "":
            msg["address"] = address
        if patches > 0:
            msg["patches"] = patches
        if date != "":
            msg["date"] = date
        if len(refs) > 0:
            msg["refs"] = refs
        if ack > 0:
            msg["ack"] = ack
        ret = 0
    except:
        msg = {}
        msg["msgid"] = msgid
        msg["url"] = url
        msg["subject"] = subject
        msg["patches"] = patches
        msg["author"] = author
        msg["address"] = address
        msg["date"] = date
        msg["ack"] = ack
        msg["refs"] = refs
        messagesdb[mailid] = msg
        ret = 1

    if patches != 0:
        add_patchesdb(mailid, msgid, subject, date, [], [],
                      None, None, None, None, None, url)

    if refs != None:
        for ref in refs:
            if refsdb.has_key(ref):
                referers = refsdb[ref]
                referers.append(mailid)
            else:
                refsdb[ref] = [mailid]

    return ret

#
# loading from XML and building the database
#
def load_one_message(message):
    try:
        refs=[]
        msgid=message.prop("id")
        author=message.prop("author")
        address=message.prop("address")
        mailid=message.prop("mailid")
        date=message.prop("date")
        subject=message.xpathEval("string(subject)")
        url=message.xpathEval("string(url)")
        references=message.xpathEval("ref")
        try:
            for ref in references:
                refs.append(ref.content)
        except:
            print "Failed to parse references for %s" % (mailid), sys.exc_info()
        try:
            patches=int(message.prop("patches"))
        except:
            patches=0
        try:
            ack=int(message.prop("ack"))
        except:
            ack=0
        ret = add_messagedb(msgid, url, author, address, mailid, subject,
                            date, patches, ack, refs)
    except:
        print "Failed to load one message from the database", sys.exc_info()
        return 0
    return ret

def load_messages(filename):
    try:
        doc = libxml2.parseFile(filename)
    except:
        print "Failed to read and parse %s" % filename
        return 0
    nb_messages = 0
    too_old = 0
    ctxt = doc.xpathNewContext()
    messages = ctxt.xpathEval("//message")
    for message in messages:
        ret = load_one_message(message)
        if ret == -1:
            too_old += 1
        else:
            nb_messages += ret
    doc.freeDoc()
    print "loaded %d messages from %s, discarded %d old" % (nb_messages,
           filename, too_old)


###################################################################
#
# Patches lifecycle checking logic
#
###################################################################

#
# Patch set detection:
# a patch set in general, is not referencing any other messages
# and is referenced by multiple messages containing patches
# but doesn't contain patch itself
#
def patchset_detection():
    for m in messagesdb:
        msg = messagesdb[m]
        if msg.has_key('refs') and len(msg['refs']) > 0:
            continue
        if msg['patches'] > 0:
            continue
        if verbose:
            print "checking %s as potential patch set" % (msg['msgid'])
        if refsdb.has_key(m):
            refs = refsdb[m]
            subpatches = 0
            patchset=[]
            for r in refs:
                if messagesdb.has_key(r):
                    ref = messagesdb[r]
                    if ref['patches'] > 0:
                        subpatches += 1
                        patchset.append(r)
            if subpatches > 0:
                if verbose:
                    print "%s seems a patch set with %d patches" % (
                                 msg['msgid'], subpatches)
                patchsetsdb[m] = patchset
                for p in patchset:
                    try:
                        patch = patchesdb[p]
                        patch['patchset'] = m
                    except:
                        print "Patch %s from patchset %s was not found" % (
                              p, m) , sys.exc_info()

#
# Utilities for string cleanups and comparisons
#

def string_matcher(str1, str2):
    #
    # see documentation on difflib,
    #
    s = difflib.SequenceMatcher(lambda x: x == " ", str1, str2)
    if s.ratio() > 0.6:
        return 1
    return 0

def email_matcher(str1, str2):
    #
    # for email after sanitizing you really want a greater match ratio
    #
    s = difflib.SequenceMatcher(lambda x: x == " ", str1, str2)
    if s.ratio() > 0.8:
        return 1
    return 0

def mail_subject_cleanup(raw):
    # cleanup the email subject strings, for example
    # removal of mailing list header and [PATCH ...] informations
    header = raw.find('[')
    while header >= 0:
        end = raw[header+1:].find(']')
        if end >= 0 and end <= 20:
            raw = raw[header + end + 2:]
        else:
            break
        header = raw.find('[')

    # clean up spaces
    try:
        raw = string.join(raw.split())
    except:
        pass

    return raw

#
# ACK and reviews checking:
#
def ack_checking():
    for p in patchesdb:
        patch = patchesdb[p]
        msg = messagesdb[p]
        if refsdb.has_key(p):
            refs = refsdb[p]
            if verbose:
                print "found refs for patch %s: %s" % (p, refs)
            for r in refs:
                if messagesdb.has_key(r):
                    m = messagesdb[r]
                    if m["ack"] > 0:
                        if r not in patch["acks"]:
                            patch["acks"].append(r)
                        # save that message r acks message p
                        acksdb[r] = p
                    if m['author'] != msg['author']:
                        if r not in patch["reviews"]:
                            patch["reviews"].append(r)

    # Look for ACK and reviews for patch set
    for ps in patchsetsdb:
        patchset = patchsetsdb[ps]
        msg = messagesdb[p]
        if refsdb.has_key(ps):
            refs = refsdb[ps]
            for r in refs:
                if messagesdb.has_key(r):
                    m = messagesdb[r]
                    # The message should only have one reference
                    # the patchset, if more than that it's an ACK
                    # for a subpatch only
                    if len(m["refs"]) != 1:
                        continue

                    if m["ack"] > 0:
                        if verbose:
                            print "message %s acks patchset %s" % (
                                   m['msgid'], ps)
                        for p in patchset:
                            if patchesdb.has_key(p):
                                patch = patchesdb[p]
                                if r not in patch["acks"]:
                                    patch["acks"].append(r)
                    # reviews should really be done on a patch by patch basis
                    # if m["author"] != msg['author']:
                    #     if 1:
                    #         print "message %s reviews patchset %s" % (
                    #                m['msgid'], ps)
                    #     for p in patchset:
                    #         if patchesdb.has_key(p):
                    #             patch = patchesdb[p]
                    #             if r not in patch["acks"]:
                    #                 patch["reviews"].append(r)

#
# Commits checking:
#
def email_lookup(mailaddress):
    emails = gitimport.emailsdb.keys()
    for email in emails:
        if email_matcher(email, mailaddress):
            return email
    return ""

def author_lookup(mailauthor):
    authors = gitimport.authorsdb.keys()
    for author in authors:
        if email_matcher(author, mailauthor):
            return author
    return ""

def days_before(date1, date2):
    try:
        s1 = time.mktime(time.strptime(date1, "%Y%m%d %H:%M:%S"))
        s2 = time.mktime(time.strptime(date2, "%Y%m%d %H:%M:%S"))
    except:
        return False
    return (s1 + 86400 < s2)

def checking_commits():
    commit_found = 0
    #
    # go through the submitted patch database and try to find
    # a match in the commited patches database
    #
    for p in patchesdb:
        patch = patchesdb[p]
        date = patch['date']
        # skip patches we know are already commited
        if patch['commit'] != None and len(patch['commit']) == 40:
            continue

        mailsubject = patch['subject']
        msg = messagesdb[p]
        mailauthor = msg['author']
        mailaddress = msg['address']

        #
        # Lookup for actual patch commit author name and addresses
        # and cleanup the topic to make it more like a commit line
        #
        author = author_lookup(mailauthor)
        email = email_lookup(mailaddress)
        subject = mail_subject_cleanup(mailsubject)

        #
        # First try to do a strict lookup
        #
        try:
            uuid = gitimport.lookup_patch(subject, author, email)
            if uuid != "":
                if verbose:
                    print "found strict matching commit for patch %s" % (p)

                commit_found += 1
                commit = gitimport.commitsdb[uuid]
                patch["cdate"] = commit['date']
                patch["commit"] = uuid
                patch["author"] = commit['author']
                patch["email"] = commit['email']
        except:
            uuid = ""
        if uuid != "":
            commit_found += 1
            continue

        #
        # Second try a more relaxed lookup
        # since it's about heuristics, the code for scanning and matching is
        # kept in this module
        #
        for c in gitimport.commitsdb.keys():
            commit = gitimport.commitsdb[c]
            cdate = commit['date']
            # a priori commits are later than patch submission,
            # though with timezones and mail propagation one should
            # allow commits before post to soem extent
            if days_before(cdate, date):
                continue
            if string_matcher(commit['subject'], subject):
                if email_matcher(commit['email'], mailaddress) or \
                   email_matcher(commit['author'], mailauthor):
                    if verbose:
                        print "found lax matching commit for patch %s" % (p)

                    commit_found += 1
                    patch["cdate"] = commit['date']
                    patch["commit"] = c
                    patch["author"] = commit['author']
                    patch["email"] = commit['email']
                #
                # Special case, sometime the commiter also fold a patch of his
                # own inside a commit. In that case the message has both an
                # ACK and a patch, and we should look for the patch as being
                # commited under the ACK'ed patch name
                #
                elif msg['ack'] == 1 and msg['patches'] == 1:
                    if acksdb.has_key(p):
                        orig = acksdb[p]
                        if patchesdb.has_key(orig):
                            op = patchesdb[orig]
                            if op['commit'] != None and len(op['commit']) == 40:
                                if verbose:
                                    print "folded in patch %s in %s" % (p, orig)
                                patch["cdate"] = op["cdate"]
                                patch["commit"] = op["commit"]
                                patch["author"] = mailauthor
                                patch["email"] = mailaddress

    return commit_found


###################################################################
#
# Reporting and Statistics
#
###################################################################

def show_statistics():
    print "Messages indexed: %d" % (len(messagesdb))
    print "Patches found   : %d" % (len(patchesdb))
    print "Patchsets found : %d" % (len(patchsetsdb))
    print "References found: %d" % (len(refsdb))
    nb_review = 0
    for p in patchesdb:
        patch = patchesdb[p]
        if len(patch["reviews"]) > 0:
            nb_review += len(patch["reviews"]) 
    print "patch reviews   : %d" % (nb_review)
    nb_acks = 0
    for m in messagesdb:
        msg = messagesdb[m]
        if msg["ack"] > 0:
            nb_acks += 1
    print "ACK detected    : %d" % (nb_acks)
    nb_acked = 0
    for p in patchesdb:
        patch = patchesdb[p]
        if len(patch["acks"]) > 0:
            nb_acked += 1
    print "ACK'ed patches  : %d" % (nb_acked)
    nb_commited = 0
    for p in patchesdb:
        patch = patchesdb[p]
        if patch["commit"] != None and len(patch["commit"]) == 40:
            nb_commited += 1
    print "Commited patches: %d" % (nb_commited)

# compute the delay in days
def compute_delay(d):
    try:
        t = time.strptime(d, "%Y%m%d %H:%M:%S")
    except:
        print "Failed to scan date %s" % (d), sys.exc_info()
        return 0
    sec = time.mktime(t)
    cur = time.mktime(time.localtime())
    days = int((cur - sec) / 86400)
    return days


def get_lagging():
    lagging = []
    cutoff = config.get_patch_cutoff()
    try:
        excludes_pattern = string.strip(config.get_patch_excludes())
        if excludes_pattern != "":
            excludes = re.compile(excludes_pattern)
        else:
            excludes = None
    except:
        excludes = None

    # Work out from the oldest patches submitted
    k = patchesdb.keys()
    l = sorted(k, key=lambda x: patchesdb[x]['date'])
    for p in l:
        patch = patchesdb[p]
        #
        # Skip patches which were commited
        #
        if patch["commit"] != None and len(patch["commit"]) == 40:
            continue

        #
        # Skip patches matching the exclude patterns
        #
        if excludes != None and re.search(excludes, patch["subject"]):
            continue

        #
        # TODO: detect superseeded patches and also ignore them
        #

        #
        # Look for patches without ACK or review
        #
        if len(patch["acks"]) == 0 and len(patch["reviews"]) == 0:
            msg = messagesdb[p]
            d = msg["date"]
            author = msg["author"]
            lag = compute_delay(d)
            if lag > config.get_patch_maxlag() and \
                    (not cutoff or lag < cutoff):
                lagging.append((p, lag, author, msg["url"], msg["subject"]))
                if verbose:
                    print "Lag(%d) from %s : %s" % (
                          lag, author, msg["subject"][0:40])
                    if msg["url"] != "":
                        print "%s" % (msg["url"])
    return lagging

def initialize():
    # try to load the previous XML history
    load_patches(config.get_patches_dbname())
    load_messages(config.get_mail_dbname())

    # we need git data too
    gitimport.initialize()

    # compute acks etc
    patchset_detection()
    ack_checking()
    ret = checking_commits()
    if ret != 0:
        print "Found %d commits for patches" % (ret)

def save_lag(f, lag):
    try:
        (p, lag, author, url, subject) = lag
        f.write("  <lag days='%d' author='%s'>\n" % (lag, author))
        f.write("    <url>%s</url>\n" % (url))
        f.write("    <subject>%s</subject>\n" % (subject))
        f.write("  </lag>")
    except:
        return 0
    return 1


def save_lagging(filename, lagging):
    try:
        f = open(filename, 'w')
    except:
        print "Failed to open %s for writing" % filename
        return 0
    n = 0
    f.write("<lagging count='%d'>\n" % (len(lagging)))
    for lag in lagging:
        n += save_lag(f, lag)
    f.write("</lagging>\n")
    print "Saved %d lagging to %s\n" % (n, filename)

def save(lagging):
    # save stuff
    save_patches(config.get_patches_dbname())
    gitimport.save()
    save_lagging("lagging.xml", lagging)

def main():
    initialize()

    # show statistics
    show_statistics()
    lagging = get_lagging()
    for s in lagging:
        (p, lag, author, url, subject) = s
        print "Lag(%d) from %s : %s" % (
              lag, author, subject[0:40])
        print "%s" % (url)

    save(lagging)


if __name__ == "__main__":
    main()
