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

# -*- coding: utf-8 -*-
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
from pyvapid import Vapid

__version__ = '1.0.1'
__license__ = 'MIT'

def __database_row_factory__(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def __database__(func):
    def __init_database__(*args, **kwargs):
        s = args[0]

        if not s.__dbConn__:
            s.__dbConn__ = db_connect(s.__dbName__)
            s.__dbConn__.row_factory = __database_row_factory__
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

    return __init_database__

def __async__(func):
    def __thread_wrapper__(*args, **kwargs):
        start_new_thread(func, args, kwargs)

    return __thread_wrapper__


class Pusher:
    __vapid__ = None
    __verbose__ = True

    __dbName__ = None
    __dbConn__= None
    __db__ = None

    __RE_URL__ = r"(https?://(?:[\w-]+\.)*[\w-]+(?::\d+)?)(?:/.*)?"

    def __init__(s, dbName="subscriptors.db", verbose=False):
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

    def __print__(s, msg): print "[ SolidWebPusher ] %s" % msg

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
        s.__verbose__ = value

    def getPublicKey(s):
        return "\x04" + s.__vapid__.public_key.to_string()

    def getPrivateKey(s):
        return s.__vapid__.private_key.to_string()

    def getB64PublicKey(s):
        return base64.b64encode(s.getPublicKey())

    def getB64PrivateKey(s):
        return base64.b64encode(s.getPrivateKey())

    def getUrlB64PublicKey(s):
        return base64.urlsafe_b64encode(s.getPublicKey()).strip("=")

    def getUrlB64PrivateKey(s):
        return base64.urlsafe_b64encode(s.getPrivateKey()).strip("=")

    @__async__
    def sendNotification(s, subscriptionInfo, data):
        subscriptionInfo = json.loads(subscriptionInfo)

        if type(data) == dict:
            data = json.dumps(data)

        base_url = re.search(s.__RE_URL__, subscriptionInfo["endpoint"]).group(1)

        encrypted = s.__encrypt__(
            subscriptionInfo["keys"]["p256dh"],
            subscriptionInfo["keys"]["auth"],
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
            subscriptionInfo["endpoint"],
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
    def notify(s, idSession, data):
        s.sendNotification(s.getSubscription(idSession), data)

    @__database__
    def notifyAll(s, data, idGroup=None, exceptList=[]):
        condition = " WHERE group_id="+idGroup if idGroup != None else ""

        for row in s.__db__.execute("SELECT * FROM subscriptors"+condition).fetchall():
            if row["subscription"] not in exceptList:
                s.sendNotification(row["subscription"], data)

    @__database__
    def newSubscription(s, idSession, subscription, idGroup=0):
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
    def getIdSession(s, subscription):
        res = s.__db__.execute(
                "SELECT session_id FROM subscriptors WHERE subscription=?",
                (subscription,)
            ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getSubscription(s, idSession):
        res = s.__db__.execute(
                "SELECT subscription FROM subscriptors WHERE session_id=?",
                (idSession,)
            ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getGroupId(s, idSession):
        res = s.__db__.execute(
                "SELECT group_id FROM subscriptors WHERE session_id=?",
                (idSession,)
            ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def removeSubscription(s, idSession):
        s.__db__.execute("DELETE FROM subscriptors WHERE session_id = ?", (idSession,))
        s.__dbConn__.commit()