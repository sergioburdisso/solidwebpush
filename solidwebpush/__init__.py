# -*- coding: utf-8 -*-

# The MIT License (MIT)
#
# Copyright (c) 2017 Sergio Burdisso
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import re
import json
import time
import base64
import http_ece
import requests
import pyelliptic

from sqlite3 import connect as db_connect
from thread import start_new_thread
from py_vapid import Vapid

__version__ = '1.0.9'
__license__ = 'MIT'

def __doc_from__(docfunc):
    """ a @decorator """
    def __wrapper__(func):
        func.__name__= docfunc.__name__
        func.__doc__= docfunc.__doc__
        return func
    return __wrapper__

def __database__(func):
    """ a @decorator """
    @__doc_from__(func)
    def __init_database__(*args, **kwargs):
        s = args[0]

        if not s.__dbConn__:
            s.__dbConn__ = db_connect(s.__dbName__)
            s.__dbConn__.row_factory = lambda cursor,row: \
                                            dict((
                                                (col[0], row[idx]) for idx, col in enumerate(cursor.description)
                                            ))
            s.__db__ = s.__dbConn__.cursor()

            try:
                s.__db__.executescript('''
                    CREATE TABLE subscriptors (
                        session_id VARCHAR(256) NOT NULL PRIMARY KEY,
                        subscription VARCHAR(512) NOT NULL,
                        group_id INT NOT NULL
                    );
                ''')
                s.__dbConn__.commit()
            except:pass 
            
            result = func(*args, **kwargs)

            s.__dbConn__.close()
            s.__dbConn__ = None
        else:
            result = func(*args, **kwargs)

        return result

    __init_database__.__name__=func.__name__
    __init_database__.__doc__=func.__doc__

    return __init_database__

def __async__(func):
    """ a @decorator """
    @__doc_from__(func)
    def __thread_wrapper__(*args, **kwargs):
        start_new_thread(func, args, kwargs)

    return __thread_wrapper__


class Pusher:
    """
    Instantiate this class to integrate Web Push Notifications
    to your server. Objects of this class will create your public
    and private key, track your subscriptions, notify your clients,
    and do all the required work for you.

    e.g.

        from solidwebpush import Pusher

        pusher = Pusher()

        #what's my base64-encoded public key?
        print pusher.getB64PublicKey()

        subscription = '{Alice's serviceWorker subscription to the Message Server}'

        #notify Alice
        pusher.sendNotification(subscription, "Hello World!")

        #or
        #permanently subscribe Alice 
        pusher.newSubscription(alice_session_id, subscription)

        #so that, from now on we can notify her by
        pusher.notify(alice_session_id, "Hello World")

        #or notify all the permanently subscribed clients
        pusher.notifyAll("Hello World")

    (Please, visit https://github.com/sergioburdisso/solidwebpush for more details.)
    """
    __vapid__ = None
    __verbose__ = False

    __dbName__ = None
    __dbConn__= None
    __db__ = None

    __RE_URL__ = r"(https?://(?:[\w-]+\.)*[\w-]+(?::\d+)?)(?:/.*)?"

    def __init__(s, dbName="subscriptors.db", verbose=False):
        """
        Class constructor

        :param dbName: The [optional] name ("subscriptors.db" by default) of the file in
                       which subscriptions will be stored in.
                       This is only required if methods like newSubscription will be used.
        :type dbName: str
        :param verbose: An optional value, to enabled or disabled the "verbose mode" (False by default)
        :type verbose: bool
        """
        s.__verbose__ = verbose
        s.__dbName__ = dbName

        if not os.path.exists('private_key.pem'):
            s.__print__("No private_key.pem file found")
            Vapid().save_key('private_key.pem')
            s.__print__("private_key.pem file created")

        s.__vapid__ = Vapid('private_key.pem')
        if not os.path.exists('public_key.pem'):
            s.__print__("No public_key.pem file found")
            s.__vapid__.save_public_key('public_key.pem')
            s.__print__("public_key.pem file created")

        if verbose:
            s.__print__("PublicKey: %s" % s.getB64PublicKey())
            #s.__print__("PrivateKey: %s" % s.getPrivateKey())

    def __print__(s, msg): print "[ SolidWebPush ] %s" % msg

    def __b64rpad__(s, b64str):
        return b64str + b"===="[:len(b64str) % 4]

    def __encrypt__(s, userPublicKey, userAuth, payload):
        userPublicKey = userPublicKey.encode("utf8")
        rawUserPublicKey = base64.urlsafe_b64decode(s.__b64rpad__(userPublicKey))

        userAuth = userAuth.encode("utf8")
        rawUserAuth = base64.urlsafe_b64decode(s.__b64rpad__(userAuth))

        salt = os.urandom(16)

        localCurve = pyelliptic.ECC(curve="prime256v1")
        localCurveId = base64.urlsafe_b64encode(localCurve.get_pubkey()[1:])

        payload = payload.encode("utf8")

        http_ece.keys[localCurveId] = localCurve
        http_ece.labels[localCurveId] = "P-256"

        encrypted = http_ece.encrypt(
            payload,
            keyid= localCurveId,
            dh= rawUserPublicKey,
            salt= salt,
            authSecret= rawUserAuth
        )

        return {
            'dh': base64.urlsafe_b64encode(localCurve.get_pubkey()).strip(b'='),
            'salt': base64.urlsafe_b64encode(salt).strip(b'='),
            'body': encrypted
        }

    def setVerbose(s, value):
        """
        Enables and disables the verbose mode (disabled by default).
        When verbose mode is active, some internal messages are going
        to be displayed, as well as the responses from the Message Server.

        :param value: True to enable or False to disable
        :type value: bool
        """
        s.__verbose__ = value

    def getPublicKey(s):
        """
        :returns: the raw public key
        :rtype: str
        """
        return "\x04" + s.__vapid__.public_key.to_string()

    def getPrivateKey(s):
        """
        (probably you won't care about private key at all)

        :returns: the raw private key
        :rtype: str
        """
        return s.__vapid__.private_key.to_string()

    def getB64PublicKey(s):
        """
        returns the string you're going to use when subscribing your serviceWorker.
        (as long as you're planning to decode it using JavaScript's atob function)

        :returns: Base64-encoded version of the public key
        :rtype: str
        """
        return base64.b64encode(s.getPublicKey())

    def getB64PrivateKey(s):
        """
        (probably you won't care about private key at all)

        :returns: Base64-encoded version of the private key
        :rtype: str
        """
        return base64.b64encode(s.getPrivateKey())

    def getUrlB64PublicKey(s):
        """
        This is the string you're going to use when subscribing your serviceWorker.
        (so long as you're planning to decode it using a function like urlB64ToUint8Array from 
        https://developers.google.com/web/fundamentals/getting-started/codelabs/push-notifications/)

        :returns: URLSafe-Base64-encoded version of the public key
        :rtype: str
        """
        return base64.urlsafe_b64encode(s.getPublicKey()).strip("=")

    def getUrlB64PrivateKey(s):
        """
        (probably you won't care about private key at all)

        :returns: URLSafe-Base64-encoded version of the private key
        :rtype: str
        """
        return base64.urlsafe_b64encode(s.getPrivateKey()).strip("=")

    @__async__
    def sendNotification(s, subscription, data):
        """
        sendNotification(subscription, data)
        pushes a notification carrying <data> to
        the client associated with the <subscription>.

        :param subscription: the client's subscription JSON object
        :type subscription: str
        :param data: A string or a dict object to be sent.
                     The dict will be converted into a JSON string before being sent.
                     An example of a dict object would be: {"title": "hey Bob!", "body": "you rock"}
        :type data: str or dict
        """
        subscription = json.loads(subscription)

        if type(data) == dict:
            data = json.dumps(data)

        base_url = re.search(s.__RE_URL__, subscription["endpoint"]).group(1)

        encrypted = s.__encrypt__(
            subscription["keys"]["p256dh"],
            subscription["keys"]["auth"],
            data
        )

        jwtpayload = {
            "aud": base_url,
            "exp": int(time.time()) + 60*60*12,
            "sub": "mailto:admin@yamanouchihnos.com"
        }

        headers = s.__vapid__.sign(jwtpayload)
        headers["Crypto-Key"] = "dh=%s;p256ecdsa=%s" % (encrypted["dh"], s.getUrlB64PublicKey())
        headers["TTL"] = 43200 #seconds
        headers["Content-Type"] = "application/octet-stream"
        headers['Content-Encoding'] = 'aesgcm';
        headers['Encryption'] = 'salt=' + encrypted["salt"];

        r = requests.post(
            subscription["endpoint"],
            data=encrypted["body"],
            headers=headers
        )

        if s.__verbose__:
            s.__print__(
                "Message Server response was: \nStatus: %d\nBody: %s"
                %
                (r.status_code, r.text)
            )

    @__database__
    def newSubscription(s, idSession, subscription, idGroup=0):
        """
        newSubscription(idSession, subscription, idGroup=0)
        Subscribes the client by permanently storing its <subscription> and group id (0 by default).
        This will allow you to push notifications using the client id (<idSession>) instead of the
        <subscription> object.

        Groups help you organize subscribers. For instance, suppose you want to notify
        Bob by sending a notification to all of his devices. If you previously
        subscribed each one of his devices to the same group, let's say 13, then calling
        notifyall with 13 will push notifications to all of them:

            BobsGroup = 13
            ...
            pusher.newSubscription(BobsTabletSessionId, subscription0, BobsGroup)
            ...
            pusher.newSubscription(BobsLaptopSessionId, subscription1, BobsGroup)
            ...
            pusher.newSubscription(BobsMobileSessionId, subscription2, BobsGroup)
            ...
            pusher.notifyall(BobsGroup)

        :param idSession: The client's identification (e.g. a cookie or other session token)
        :type idSession: str
        :param subscription: The client's subscription JSON object
        :type subscription: str
        :param idGroup: an optional Group ID value (0 by default)
        :type idGroup: int
        """
        if not s.getSubscription(idSession):
            oldIdSession = s.getIdSession(subscription)
            if oldIdSession:
                s.removeSubscription(oldIdSession)
            s.__db__.execute(
                "INSERT INTO subscriptors (session_id, subscription, group_id) VALUES (?,?,?)",
                (idSession, subscription, idGroup)
            )
        else:
            s.__db__.execute(
                "UPDATE subscriptors SET subscription=?, group_id=? WHERE session_id=?",
                (subscription, idGroup, idSession,)
            )
        s.__dbConn__.commit()

    @__database__
    def removeSubscription(s, idSession):
        """
        removeSubscription(idSession)
        Unsubscribes the client by permanently removing its <subscription> and group id (0 by default).

        :param idSession: The client's identification (e.g. a cookie or other session token)
        :type idSession: str
        """
        s.__db__.execute("DELETE FROM subscriptors WHERE session_id = ?", (idSession,))
        s.__dbConn__.commit()

    @__database__
    def notify(s, idSession, data):
        """
        notify(idSession, data)
        pushes a notification carrying <data> to the client associated with the <idSession>.
        <idSession> is the value passed to the newSubscription method when storing the client's 
        subscription object.

        :param idSession: The client's identification (e.g. a cookie or other session token)
        :type idSession: str
        :param data: A string or a dict object to be sent.
                     The dict will be converted into a JSON string before being sent.
                     An example of a dict object would be: {"title": "hey Bob!", "body": "you rock"}
        :type data: str or dict
        """
        s.sendNotification(s.getSubscription(idSession), data)

    @__database__
    def notifyAll(s, data, idGroup=None, exceptList=[]):
        """
        notifyAll(data, idGroup=None, exceptList=[])
        When no <idGroup> is given, notify all subscribers (except for those in <exceptList>).
        Otherwise, it only notifies all members of the <idGroup> group (except for those in <exceptList>).

        :param data: A string or a dict object to be sent.
                     The dict will be converted into a JSON string before being sent.
                     An example of a dict object would be: {"title": "hey Bob!", "body": "you rock"}
        :type data: str or dict
        :param idGroup: an optional Group ID value (0 by default)
        :type idGroup: int
        :param exceptList: The list of sessions ids to be excluded ([] by default).
        :type exceptList: list (of <session ID>s)
        """
        condition = " WHERE group_id="+idGroup if idGroup != None else ""

        for row in s.__db__.execute("SELECT * FROM subscriptors"+condition).fetchall():
            if row["session_id"] not in exceptList:
                s.sendNotification(row["subscription"], data)

    @__database__
    def getIdSession(s, subscription):
        """
        getIdSession(subscription)
        Given a subscription object returns the session id associated with it.

        :param subscription: The client's subscription JSON object
        :type subscription: str
        :returns: the session id associated with subscription
        :rtype: str
        """
        res = s.__db__.execute(
                "SELECT session_id FROM subscriptors WHERE subscription=?",
                (subscription,)
            ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getSubscription(s, idSession):
        """
        getSubscription(idSession)
        Given a session id returns the subscription object associated with it.

        :param idSession: A session id
        :type idSession: str
        :returns: The client's subscription JSON object associated with the session id
        :rtype: str
        """
        res = s.__db__.execute(
                "SELECT subscription FROM subscriptors WHERE session_id=?",
                (idSession,)
            ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getGroupId(s, idSession):
        """
        getGroupId(idSession)
        Given a session id returns the group id it belongs to.

        :param idSession: A session id
        :type idSession: str
        :returns: a group id value
        :rtype: int
        """
        res = s.__db__.execute(
                "SELECT group_id FROM subscriptors WHERE session_id=?",
                (idSession,)
            ).fetchone()
        return res.values()[0] if res else None
