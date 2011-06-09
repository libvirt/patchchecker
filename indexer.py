#!/usr/bin/python -u
#
# The indexer for patches and acks, works out of a mail web archive,
# tuned for MHonArc v2.6.x output
#
# This saves the messages to an XML database file for later processing
# it doesn't gather content but check if there is patches or acks, and
# the various IDs needed to reconstruct the chain like mail id, author
# and references
#

import libxml2
import shutil
import sys
import string
import os
import time

import config

verbose = 0

#
# We are not interested in parsing errors here
#
def callback(ctx, str):
    return
libxml2.registerErrorHandler(callback, None)

def usage():
    print "usage ...."

#########################################################################
#                                                                       #
#                  Word dictionary and analysis routines                #
#                                                                       #
#########################################################################

#
# top 100 english word without the one len < 3 + own set
#
dropWords = {
    'the':0, 'this':0, 'can':0, 'man':0, 'had':0, 'him':0, 'only':0,
    'and':0, 'not':0, 'been':0, 'other':0, 'even':0, 'are':0, 'was':0,
    'new':0, 'most':0, 'but':0, 'when':0, 'some':0, 'made':0, 'from':0,
    'who':0, 'could':0, 'after':0, 'that':0, 'will':0, 'time':0, 'also':0,
    'have':0, 'more':0, 'these':0, 'did':0, 'was':0, 'two':0, 'many':0,
    'they':0, 'may':0, 'before':0, 'for':0, 'which':0, 'out':0, 'then':0,
    'must':0, 'one':0, 'through':0, 'with':0, 'you':0, 'said':0,
    'first':0, 'back':0, 'were':0, 'what':0, 'any':0, 'years':0, 'his':0,
    'her':0, 'where':0, 'all':0, 'its':0, 'now':0, 'much':0, 'she':0,
    'about':0, 'such':0, 'your':0, 'there':0, 'into':0, 'like':0, 'may':0,
    'would':0, 'than':0, 'our':0, 'well':0, 'their':0, 'them':0, 'over':0,
    'down':0,
    'net':0, 'www':0, 'bad':0, 'Okay':0, 'bin':0, 'cur':0,
}

wordsDict = {}
wordsDictHTML = {}
wordsDictArchive = {}

def cleanupWordsString(str):
    str = string.replace(str, ".", " ")
    str = string.replace(str, "!", " ")
    str = string.replace(str, "?", " ")
    str = string.replace(str, ",", " ")
    str = string.replace(str, "'", " ")
    str = string.replace(str, '"', " ")
    str = string.replace(str, ";", " ")
    str = string.replace(str, "(", " ")
    str = string.replace(str, ")", " ")
    str = string.replace(str, "{", " ")
    str = string.replace(str, "}", " ")
    str = string.replace(str, "<", " ")
    str = string.replace(str, ">", " ")
    str = string.replace(str, "=", " ")
    str = string.replace(str, "/", " ")
    str = string.replace(str, "*", " ")
    str = string.replace(str, ":", " ")
    str = string.replace(str, "#", " ")
    str = string.replace(str, "\\", " ")
    str = string.replace(str, "\n", " ")
    str = string.replace(str, "\r", " ")
    str = string.replace(str, "\xc2", " ")
    str = string.replace(str, "\xa0", " ")
    return str

def cleanupDescrString(str):
    str = string.replace(str, "'", " ")
    str = string.replace(str, "\n", " ")
    str = string.replace(str, "\r", " ")
    str = string.replace(str, "\xc2", " ")
    str = string.replace(str, "\xa0", " ")
    l = string.split(str)
    str = string.join(str)
    return str

def splitIdentifier(str):
    ret = []
    while str != "":
        cur = string.lower(str[0])
        str = str[1:]
        if ((cur < 'a') or (cur > 'z')):
            continue
        while (str != "") and (str[0] >= 'A') and (str[0] <= 'Z'):
            cur = cur + string.lower(str[0])
            str = str[1:]
        while (str != "") and (str[0] >= 'a') and (str[0] <= 'z'):
            cur = cur + str[0]
            str = str[1:]
        while (str != "") and (str[0] >= '0') and (str[0] <= '9'):
            str = str[1:]
        ret.append(cur)
    return ret

#########################################################################
#                                                                       #
#                  Mail archives parsing and analysis                   #
#                                                                       #
#########################################################################


messagesdb={}

def add_messagedb(msgid, url = "", author = "", address = "", mailid = "", subject = "", date=None, patches=0, ack=0, refs=[]):
    if msgid == None or msgid == "":
        return

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

    try:
        msg = messagesdb[msgid]
        if mailid != "":
            msg["mailid"] = mailid
        if subject != "":
            msg["subject"] = subject
        if author != "":
            msg["author"] = author
        if address != "":
            msg["address"] = address
        if url != "":
            msg["url"] = url
        if patches > 0:
            msg["patches"] = patches
        if date != None:
            msg["date"] = date
        if len(refs) > 0:
            msg["refs"] = refs
        if ack > 0:
            msg["ack"] = ack
    except:
        msg = {}
        msg["mailid"] = mailid
        msg["subject"] = subject
        msg["patches"] = patches
        msg["author"] = author
        msg["address"] = address
        msg["date"] = date
        msg["ack"] = ack
        msg["refs"] = refs
        msg["url"] = url
        messagesdb[msgid] = msg

def is_space(c):
    if c == ' ' or c == '\t' or c == '\n' or c == '\r':
        return 1
    return 0

def unescape(raw):
    raw = string.replace(raw, '&amp;', '&')
    raw = string.replace(raw, '&lt;', '<')
    raw = string.replace(raw, '&gt;', '>')
    raw = string.replace(raw, '&apos;', "'")
    raw = string.replace(raw, '&quot;', '"')

    # remove the character references too, as they are kept in comments
    cref = raw.find("&#")
    while cref >= 0:
        idx = cref + 2
        val = 0
        while raw[idx] >= '0' and raw[idx] <= '9':
            val = val * 10 + ord(raw[idx]) - 48
            idx += 1
        if raw[idx] == ';':
            raw = raw[0:cref] + chr(val) + raw[idx+1:]
        else:
            break
        cref = raw.find("&#")

    return raw

def escape(raw):
    raw = string.replace(raw, '&', '&amp;')
    raw = string.replace(raw, '<', '&lt;')
    raw = string.replace(raw, '>', '&gt;')
    raw = string.replace(raw, "'", '&apos;')
    raw = string.replace(raw, '"', '&quot;')
    return raw

def save_message(f, msgid):
    msg = messagesdb[msgid]
    f.write("  <message id='%s'" % (msgid))
    if msg.has_key('mailid') and msg['mailid'] != "":
        f.write(" mailid='%s'" % (escape(msg['mailid'])))
    if msg.has_key('address') and msg['address'] != "":
        f.write(" address='%s'" % (escape(msg['address'])))
    if msg.has_key('author') and msg['author'] != "":
        f.write(" author='%s'" % (escape(msg['author'])))
    if msg.has_key('date') and msg['date'] != None:
        f.write(" date='%s'" % (msg['date']))
    if msg.has_key('patches') and msg['patches'] != None and msg['patches'] != 0:
        f.write(" patches='%s'" % (msg['patches']))
    if msg.has_key('ack') and msg['ack'] != None and msg['ack'] != 0:
        f.write(" ack='%s'" % (msg['ack']))
    f.write(">\n")
    if msg.has_key('url') and msg['url'] != "":
        f.write("    <url>%s</url>\n" % (escape(msg['url'])))
    if msg.has_key('subject') and msg['subject'] != "":
        f.write("    <subject>%s</subject>\n" % (escape(msg['subject'])))
    if msg.has_key('refs'):
        for ref in msg['refs']:
            f.write("    <ref>%s</ref>\n" % (escape(ref)))
    f.write("  </message>\n")

def save_messages(filename):
    try:
        f = open(filename, 'w')
    except:
        print "Failed to open %s for writing" % filename
    f.write("<messages>\n")
    # save the messages sorted by msgid, increasing date/time
    k = messagesdb.keys()
    l = sorted(k, key=lambda x: messagesdb[x]['date'])
    n = 0
    for message in l:
        save_message(f, message)
        n += 1
    f.write("</messages>\n")
    print "Saved %d messages to %s\n" % (n, filename)


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
        add_messagedb(msgid, url, author, address, mailid, subject, date, patches, ack, refs)
    except:
        print "Failed to load one message from the database", sys.exc_info()
        return 0
    return 1

def load_messages(filename):
    try:
        doc = libxml2.parseFile(filename)
    except:
        print "Failed to read and parse %s" % filename
        return 0
    nb_messages = 0
    ctxt = doc.xpathNewContext()
    messages = ctxt.xpathEval("//message")
    for message in messages:
        nb_messages += load_one_message(message)
    doc.freeDoc()
    print "loaded %d messages from %s" % (nb_messages, filename)

#########################################################################
#                                                                       #
#                  Mail archives parsing and analysis                   #
#                                                                       #
#########################################################################

def getXMLDatePrefix(t = None):
    if t == None:
        t = time.time()
    T = time.gmtime(t)
    month = time.strftime("%B", T)
    year = T[0]
    prefix = "%s-%s" % (year, month)
    return prefix

def getXMLDateMonth(t = None):
    if t == None:
        t = time.time()
    T = time.gmtime(t)
    month = time.strftime("%m", T)
    year = T[0]
    prefix = "%s-%s" % (year, month)
    return prefix


def getXMLDateArchive(t = None):
    if t == None:
        t = time.time()
    T = time.gmtime(t)
    month = time.strftime("%B", T)
    year = T[0]
    url = config.get_mail_archives() % (year, month)
    return url

def scanXMLMsgArchive(url, title, force = 0):
    if url == None or title == None:
        return 0

    ID = checkXMLMsgArchive(url)
    if force == 0 and ID != -1:
        return 0

    if ID == -1:
        ID = addXMLMsgArchive(url, title)
        if ID == -1:
            return 0

    try:
        if verbose:
            print "Loading %s" % (url)
        doc = libxml2.htmlParseFile(url, None);
    except:
        doc = None
    if doc == None:
        print "Failed to parse %s" % (url)
        return 0

    addStringArchive(title, ID, 20)
    ctxt = doc.xpathNewContext()
    # we are interested in author text avoid anything in blockquote
    texts = ctxt.xpathEval("//body//text()[not(ancestor::blockquote)]")
    for text in texts:
        addStringArchive(text.content, ID, 5)

    doc.freeDoc()
    return 1

def rot13(source):
    res = ""
    for c in source:
        byte = ord(c)
        cap = (byte & 32)
        byte = (byte & (~cap))
        if (byte >= ord('A')) and (byte <= ord('Z')):
            byte = ((byte - ord('A') + 13) % 26 + ord('A'))
        byte = (byte | cap)
        res += chr(byte)
    return res

def scan_text_ack(text):
    # and ACK in a line with a > or : used for quoting sounds a good indication
    ack = text.rfind("ACK ")
    if ack == 0 or (ack > 0 and is_space(text[ack - 1])):
        if verbose:
            print "ack=", ack
    else:
        ack = -1

    if ack < 0:
        ack = text.rfind("ACK\n")
        if ack == 0 or (ack > 0 and is_space(text[ack - 1])):
            if verbose:
                print "ack=", ack
        else:
            ack = -1

    if ack < 0:
        ack = text.rfind("ACK.")
        if ack == 0 or (ack > 0 and is_space(text[ack - 1])):
            if verbose:
                print "ack=", ack
        else:
            ack = -1

    if ack < 0:
        ack = text.rfind("ACK,")
        if ack == 0 or (ack > 0 and is_space(text[ack - 1])):
            if verbose:
                print "ack=", ack
        else:
            ack = -1

    if ack >= 0:
        while ack >= 0:
            if text[ack] == "\n":
                return 1
            if text[ack] == ">" or text[ack] == ":":
                return 0
            ack -= 1
        return 1
    return 0

def scan_doc_ack(doc):
    # scan the document for ACKs
    patch = 0
    ctxt = doc.xpathNewContext()
    # we are interested in author text avoid anything in blockquote
    txts = ctxt.xpathEval("//body//text()[not(ancestor::blockquote)]")
    for txt in txts:
        text = txt.content
        if scan_text_ack(text) > 0:
            if verbose:
                print "found ack\n"
            return 1

    return 0

def scan_text_patch(text):
    # a Signed of by or diff in line beginning is a good indication
    sob = text.find("Signed-off-by")
    if sob >= 0:
        if verbose:
            print "sob=", sob
    if sob == 0 or (sob > 0 and text[sob - 1] == "\n"):
        return 1
    diff = text.find("diff ")
    if diff >= 0:
        if verbose:
            print "diff=", diff
    if diff == 0 or (diff > 0 and text[diff - 1] == "\n"):
        return 1
    return 0

def scan_doc_patch(doc):
    # scan the document for patch(es)
    patch = 0
    ctxt = doc.xpathNewContext()
    # we are interested in author text avoid anything in blockquote
    txts = ctxt.xpathEval("//body//text()[not(ancestor::blockquote)]")
    for txt in txts:
        text = txt.content
        patch += scan_text_patch(text)

    if  patch > 0:
        if verbose:
            print "found patch\n"
    return patch

def scan_from_field(raw):
    author=""
    address=""
    if raw[0:5] == "From:":
        raw = raw[5:].strip()
    mail = raw.find('<')
    email = raw.rfind('>')
    if mail >= 0 and email > mail:
        author = raw[:mail].strip()
        address= raw[mail+1:email]
    else:
        author = raw
    author = string.replace(author, '"', '')
    author = string.replace(author, "'", "")

    return (author, address)

def scan_date_field(raw):
    if raw[0:5] == "Date:":
        raw = raw[5:].strip()
    tz = raw.rfind('-')
    if tz < 0:
        tz = raw.rfind('+')
    if tz > 0:
        raw = raw[:tz].strip()
    else:
        raw = raw.strip()
    try:
        t = time.strptime(raw, "%a, %d %b %Y %H:%M:%S")
        date = time.strftime("%Y%m%d %H:%M:%S", t)
    except:
        print "Failed to scan date %s" % (raw)
        date = None

    return date

def scanXMLMsgArchive(msg, msgid, title, force = 0):
    # check first that it's not already loaded
    if force == 0 and messagesdb.has_key(msgid):
        return 0

    if verbose:
        print "To scan: %s %s '%s'" % (msgid, msg, title)
    else:
        sys.stdout.write(".")

    try:
        if verbose:
            print "Loading %s" % (msg)
        doc = libxml2.htmlParseFile(msg, None)
    except:
        doc = None
    if doc == None:
        print "Failed to parse %s" % (msg)
        return 0

    # Find the message ID from the comments
    # as well as references, etc ...
    ctxt = doc.xpathNewContext()
    comments = ctxt.xpathEval("//comment()")
    mailid=""
    references=[]

    for comment in comments:
        content = comment.content.strip()
        try:
            if content[0:14] == "X-Message-Id: ":
                mailid=unescape(content[14:])
            if content[0:13] == "X-Reference: ":
                ref=unescape(content[13:])
                references.append(ref)
        except:
            print "Failed to handle comment '%s'", sys.exc_info()

    if mailid == "":
        print "Failed to find mail ID in %s\n"

    from_field = ctxt.xpathEval("string(//body//li[em = 'From'][1])")
    (author, address) = scan_from_field(from_field)

    date_field = ctxt.xpathEval("string(//body//li[em = 'Date'][1])")
    date = scan_date_field(date_field)

    try:
        patches = scan_doc_patch(doc);
    except:
        print "scan doc for patches raised exception",  sys.exc_info()
        patches = 0

    try:
        ack = scan_doc_ack(doc);
    except:
        print "scan doc for ack raised exception",  sys.exc_info()
        ack = 0

    try:
        add_messagedb(msgid, msg, author, address, mailid, title, date, patches, ack, references);
        if verbose:
            print "Added mail id to database: %s\n" % (mailid)
    except:
        print "Failed to add new message to database",  sys.exc_info()

    doc.freeDoc()
    return 1

def scanXMLDateArchive(t = None, force = 0, max_fetch = 0):
    if max_fetch <= 0:
        max_fetch = config.get_mail_max_fetch()

    url = getXMLDateArchive(t)
    prefix = getXMLDatePrefix(t)
    month = getXMLDateMonth(t)
    if verbose:
        print "loading %s" % (url)
    else:
        print "loading Web archive page"
    try:
        doc = libxml2.htmlParseFile(url, None);
    except:
        doc = None
    if doc == None:
        print "Failed to parse %s" % (url)
        return -1
    max_fetch -= 1
    ctxt = doc.xpathNewContext()
    anchors = ctxt.xpathEval("//a[@href]")
    links = 0
    newmsg = 0
    for anchor in anchors:
        href = anchor.prop("href")
        if href == None or href[0:3] != "msg":
            continue
        try:
            suffix=href[3:]
            if suffix[-5:] == ".html":
                suffix = suffix[:-5]
            links = links + 1

            url = libxml2.buildURI(href, url)
            title = anchor.content
            msgid = "%s-%s" % (month, suffix)
            loaded = scanXMLMsgArchive(url, msgid, title, force)
            newmsg = newmsg + loaded
            max_fetch -= loaded
            if max_fetch <= 0:
                return newmsg

        except:
            pass

    print "loading done"
    return newmsg

def analyzeArchives(t = None, force = 0, max_fetch = 0):
    if max_fetch <= 0:
        max_fetch = config.get_mail_max_fetch()

    num = scanXMLDateArchive(t, force, max_fetch)

    return num

#########################################################################
#                                                                       #
#          Main code: open the DB, the API XML and analyze it           #
#                                                                       #
#########################################################################

def main():
    # try to load the previous XML history
    dbname = config.get_mail_dbname()
    load_messages(dbname)

    args = sys.argv[1:]
    force = 0
    if args:
        i = 0
        while i < len(args):
            if args[i] == '--force':
                force = 1
            elif args[i] == '--archive':
                analyzeArchives(None, force, config.get_mail_max_fetch())
            elif args[i] == '--archive-year':
                i = i + 1;
                year = args[i]
                months = ["January" , "February", "March", "April", "May",
                          "June", "July", "August", "September", "October",
                          "November", "December"];
                for month in months:
                    try:
                        str = "%s-%s" % (year, month)
                        T = time.strptime(str, "%Y-%B")
                        t = time.mktime(T) + 3600 * 24 * 10;
                        analyzeArchives(t, force, 10000)
                    except:
                        print "Failed to index month archive:"
                        print sys.exc_type, sys.exc_value
            elif args[i] == '--archive-month':
                i = i + 1;
                month = args[i]
                try:
                    T = time.strptime(month, "%Y-%B")
                    t = time.mktime(T) + 3600 * 24 * 10;
                    analyzeArchives(t, force, 1000)
                except:
                    print "Failed to index month archive:"
                    print sys.exc_type, sys.exc_value
            else:
                usage()
            i = i + 1
    else:
        analyzeArchives(None, force, config.get_mail_max_fetch())

    # then save the current history
    try:
        shutil.copy (dbname, dbname + ".bak")
    except:
        pass

    try:
        save_messages(dbname)
    except:
        print "Failed to save back message database",  sys.exc_info()
        shutil.copy (dbname+ ".bak", dbname)

if __name__ == "__main__":
    main()
