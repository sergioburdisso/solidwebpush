# -*- coding: utf-8 -*-
"""
This module lets your server send Web Push Notifications to your clients.

(Please, visit https://github.com/sergioburdisso/solidwebpush for more info).

----
"""
import os
import re
import json
import time
import base64
import requests
import http_ece
import pyelliptic

from sqlite3 import connect as db_connect
from multiprocessing import Pool
from py_vapid import Vapid

__version__ = '1.2.0'
__license__ = 'MIT'


def __doc_from__(docfunc):
    """ a @decorator """
    def __wrapper__(func):
        func.__name__ = docfunc.__name__
        func.__doc__ = docfunc.__doc__
        return func
    return __wrapper__


def __database__(func):
    """ a @decorator """
    @__doc_from__(func)
    def __init_database__(*args, **kwargs):
        s = args[0]

        if not s.__dbConn__:
            s.__dbConn__ = db_connect(s.__dbName__)
            s.__dbConn__.row_factory = lambda cursor, row: \
                dict((
                    (col[0], row[idx])
                    for idx, col
                    in enumerate(cursor.description)
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
            except:
                pass

            result = func(*args, **kwargs)

            s.__dbConn__.close()
            s.__dbConn__ = None
        else:
            result = func(*args, **kwargs)

        return result

    __init_database__.__name__ = func.__name__
    __init_database__.__doc__ = func.__doc__

    return __init_database__


class Pusher:
    """
    Instantiate this class to integrate Web Push Notifications
    to your server. Objects of this class will create your public
    and private key, track your subscriptions, notify your clients,
    and do all the required work for you.

    e.g.

        >>> from solidwebpush import Pusher
        >>>
        >>> pusher = Pusher()
        >>>
        >>> #what's my base64-encoded public key?
        >>> print pusher.getB64PublicKey()
        >>>
        >>> subscription = "{Alice's serviceWorker subscription object}"
        >>>
        >>> #notify Alice
        >>> pusher.sendNotification(subscription, "Hello World!")
        >>>
        >>> #or
        >>> #permanently subscribe Alice
        >>> pusher.newSubscription(alice_session_id, subscription)
        >>>
        >>> #so that, from now on we can notify her by
        >>> pusher.notify(alice_session_id, "Hello World")
        >>>
        >>> #or notify all the permanently subscribed clients
        >>> pusher.notifyAll("Hello World")

    (for more "toy" examples visit
     https://github.com/sergioburdisso/solidwebpush/tree/master/examples)
    """
    __vapid__ = None
    __verbose__ = False

    __dbName__ = None
    __dbConn__ = None
    __db__ = None
    __pool__ = None

    __RE_URL__ = r"(https?://(?:[\w-]+\.)*[\w-]+(?::\d+)?)(?:/.*)?"

    def __init__(self, dbName="subscriptors.db", verbose=False):
        """
        Class constructor

        :param dbName: The [optional] name ("subscriptors.db" by default) of
                       the file in which subscriptions will be stored in.
                       This is only required if methods like
                       ``newSubscription`` will be used.
        :type dbName: str
        :param verbose: An optional value, to enabled or disabled the "verbose
                        mode" (False by default)
        :type verbose: bool
        """
        self.__verbose__ = verbose
        self.__dbName__ = dbName

        if not os.path.exists('private_key.pem'):
            self.__print__("No private_key.pem file found")
            Vapid().save_key('private_key.pem')
            self.__print__("private_key.pem file created")

        self.__vapid__ = Vapid('private_key.pem')
        if not os.path.exists('public_key.pem'):
            self.__print__("No public_key.pem file found")
            self.__vapid__.save_public_key('public_key.pem')
            self.__print__("public_key.pem file created")

        if verbose:
            self.__print__("PublicKey: %s" % self.getB64PublicKey())

    def __getstate__(self):
        self_dict = self.__dict__.copy()
        del self_dict['__pool__']
        return self_dict

    def __call__(self, subscription, data):
        self.__send__(subscription, data)

    def __print__(self, msg):
        print "[ SolidWebPush ] %s" % msg

    def __b64rpad__(self, b64str):
        return b64str + b"===="[:len(b64str) % 4]

    def __encrypt__(self, userPublicKey, userAuth, payload):
        userPublicKey = userPublicKey.encode("utf8")
        rawUserPublicKey = base64.urlsafe_b64decode(
            self.__b64rpad__(userPublicKey)
        )

        userAuth = userAuth.encode("utf8")
        rawUserAuth = base64.urlsafe_b64decode(self.__b64rpad__(userAuth))

        salt = os.urandom(16)

        curve = pyelliptic.ECC(curve="prime256v1")
        curveId = base64.urlsafe_b64encode(curve.get_pubkey()[1:])

        payload = payload.encode("utf8")

        http_ece.keys[curveId] = curve
        http_ece.labels[curveId] = "P-256"

        encrypted = http_ece.encrypt(
            payload,
            keyid=curveId,
            dh=rawUserPublicKey,
            salt=salt,
            authSecret=rawUserAuth
        )

        return {
            'dh': base64.urlsafe_b64encode(curve.get_pubkey()).strip(b'='),
            'salt': base64.urlsafe_b64encode(salt).strip(b'='),
            'body': encrypted
        }

    def __send__(self, subscription, data):
        subscription = json.loads(subscription)

        if type(data) == dict:
            data = json.dumps(data)

        base_url = re.search(
            self.__RE_URL__,
            subscription["endpoint"]
        ).group(1)

        encrypted = self.__encrypt__(
            subscription["keys"]["p256dh"],
            subscription["keys"]["auth"],
            data
        )

        jwtpayload = {
            "aud": base_url,
            "exp": int(time.time()) + 60 * 60 * 12,
            "sub": "mailto:admin@yamanouchihnos.com"
        }

        headers = self.__vapid__.sign(jwtpayload)
        headers["TTL"] = str(43200)
        headers["Content-Type"] = "application/octet-stream"
        headers['Content-Encoding'] = 'aesgcm'
        headers['Encryption'] = 'salt=' + encrypted["salt"]
        headers["Crypto-Key"] = "dh=%s;p256ecdsa=%s" % (
            encrypted["dh"],
            self.getUrlB64PublicKey()
        )

        r = requests.post(
            subscription["endpoint"],
            data=encrypted["body"],
            headers=headers
        )

        if self.__verbose__:
            self.__print__(
                "Message Server response was: \nStatus: %d\nBody: %s"
                %
                (r.status_code, r.text)
            )

    def setVerbose(self, value):
        """
        Enables and disables the verbose mode (disabled by default).
        When verbose mode is active, some internal messages are going
        to be displayed, as well as the responses from the Message Server.

        :param value: True to enable or False to disable
        :type value: bool
        """
        self.__verbose__ = value

    def getPublicKey(self):
        """
        :returns: the raw public key
        :rtype: str
        """
        return "\x04" + self.__vapid__.public_key.to_string()

    def getPrivateKey(self):
        """
        (probably you won't care about private key at all)

        :returns: the raw private key
        :rtype: str
        """
        return self.__vapid__.private_key.to_string()

    def getB64PublicKey(self):
        """
        Returns the string you're going to use when subscribing your
        serviceWorker.
        (as long as you're planning to decode it using JavaScript's
        ``atob`` function)

        :returns: Base64-encoded version of the public key
        :rtype: str
        """
        return base64.b64encode(self.getPublicKey())

    def getB64PrivateKey(self):
        """
        (probably you won't care about private key at all)

        :returns: Base64-encoded version of the private key
        :rtype: str
        """
        return base64.b64encode(self.getPrivateKey())

    def getUrlB64PublicKey(self):
        """
        This is the string you're going to use when subscribing your
        serviceWorker.
        (so long as you're planning to decode it using a function like
        ``urlB64ToUint8Array`` from
        https://developers.google.com/web/fundamentals/getting-started/codelabs/push-notifications/)

        :returns: URLSafe-Base64-encoded version of the public key
        :rtype: str
        """
        return base64.urlsafe_b64encode(self.getPublicKey()).strip("=")

    def getUrlB64PrivateKey(self):
        """
        (probably you won't care about private key at all)

        :returns: URLSafe-Base64-encoded version of the private key
        :rtype: str
        """
        return base64.urlsafe_b64encode(self.getPrivateKey()).strip("=")

    def sendNotification(self, subscription, data, nonblocking=False):
        """
        Pushes a notification carrying ``data`` to
        the client associated with the ``subscription`` object.
        If ``nonblocking`` is False, the program won't block waiting
        for the message to be completely sent. The ``wait()`` method
        should be used instead. (see ``wait()`` for more details)

        :param subscription: the client's subscription JSON object
        :type subscription: str
        :param data: A string or a dict object to be sent.
                     The dict will be automatically converted into a JSON
                     string before being sent.
                     An example of a dict object would be:
                     ``{"title": "hey Bob!", "body": "you rock"}``
        :type data: str or dict
        :param nonblocking: Whether to block the caller until this method
                            finishes running or not.
        :type nonblocking: bool
        """
        self.sendNotificationToAll(
            [subscription],
            data,
            nonblocking=nonblocking,
            processes=1
        )

    def sendNotificationToAll(
            self, subscriptions, data, nonblocking=False, processes=None):
        """
        Pushes a notification carrying ``data`` to
        each of the clients associated with the list of ``subscriptions``.
        If ``nonblocking`` is False, the program won't block waiting
        for all the messages to be completely sent. The ``wait()`` method
        should be used instead. (see ``wait()`` for more details)

        :param subscriptions: The list of client's subscription JSON object
        :type subscriptions: list
        :param data: A string or a dict object to be sent.
                     The dict will be automatically converted into a JSON
                     string before being sent.
                     An example of a dict object would be:
                     ``{"title": "hey Bob!", "body": "you rock"}``
        :type data: str or dict
        :param processes: The [optional] number of worker processes to use.
                          If processes is not given then the number returned by
                          os.cpu_count() is used.
        :type processes: int
        :param nonblocking: Whether to block the caller until this method
                            finishes running or not.
        :type nonblocking: bool
        """
        if not self.__pool__:
            self.__pool__ = Pool(processes)

        if nonblocking:
            pool_apply = self.__pool__.apply_async
        else:
            pool_apply = self.__pool__.apply

        for subscription in subscriptions:
            pool_apply(self, args=(subscription, data))

        if not nonblocking:
            self.__pool__.close()
            self.__pool__.join()
            self.__pool__ = None

    def wait(self):
        """
        Blocks the program and waits for all the notifications to be sent,
        before continuing.
        This only works if there exist a previous call to a method
        with the ``nonblocking`` parameter set to ``False``,
        as shown in the following example:

        >>> pusher.sendNotificationToAll(
            listOfsubscriptions,
            "Hello World",
            nonblocking=False
        )
        >>> # Maybe some other useful computation here
        >>> pusher.wait()
        """
        self.__pool__.close()
        self.__pool__.join()
        self.__pool__ = None

    @__database__
    def newSubscription(self, idSession, subscription, idGroup=0):
        """
        newSubscription(idSession, subscription, idGroup=0)
        Subscribes the client by permanently storing its ``subscription`` and
        group id (``idGroup``).
        This will allow you to push notifications using the
        client id (``idSession``) instead of its ``subscription`` object.

        Groups help you organize subscribers. For instance, suppose you
        want to notify Bob by sending a notification to all of his devices.
        If you previously subscribed each one of his devices to the same group
        let's say 13, then calling notifyall with 13 will push notifications to
         all of them:

            >>> BobsGroup = 13
            >>> ...
            >>> pusher.newSubscription(
                    BobsTabletSessionId,
                    subscription0,
                    BobsGroup
                )
            >>> ...
            >>> pusher.newSubscription(
                    BobsLaptopSessionId,
                    subscription1,
                    BobsGroup
                )
            >>> ...
            >>> pusher.newSubscription(
                    BobsMobileSessionId,
                    subscription2,
                    BobsGroup
                )
            >>> ...
            >>> pusher.notifyAll(BobsGroup)

        :param idSession: The client's identification
                          (e.g. a cookie or other session token)
        :type idSession: str
        :param subscription: The client's subscription JSON object
        :type subscription: str
        :param idGroup: an optional Group ID value (0 by default)
        :type idGroup: int
        """
        if not self.getSubscription(idSession):
            oldIdSession = self.getIdSession(subscription)
            if oldIdSession:
                self.removeSubscription(oldIdSession)
            self.__db__.execute(
                "INSERT INTO subscriptors (session_id, subscription, group_id)"
                " VALUES (?,?,?)",
                (idSession, subscription, idGroup)
            )
        else:
            self.__db__.execute(
                "UPDATE subscriptors SET subscription=?, group_id=? WHERE"
                " session_id=?",
                (subscription, idGroup, idSession,)
            )
        self.__dbConn__.commit()

    @__database__
    def removeSubscription(self, idSession):
        """
        removeSubscription(idSession)
        Unsubscribes the client by permanently removing its ``subscription``
        and group id.

        :param idSession: The client's identification (e.g. a cookie or other
                          session token)
        :type idSession: str
        """
        self.__db__.execute(
            "DELETE FROM subscriptors WHERE session_id = ?",
            (idSession,)
        )
        self.__dbConn__.commit()

    @__database__
    def notify(self, idSession, data, nonblocking=False):
        """
        notify(idSession, data)
        Pushes a notification carrying ``data`` to the client associated with
        the ``idSession``.
        ``idSession`` is the value passed to the ``newSubscription`` method
        when storing the client's subscription object.

        :param idSession: The client's identification (e.g. a cookie or other
                          session token)
        :type idSession: str
        :param data: A string or a dict object to be sent.
                     The dict will be automatically converted into a JSON
                     string before being sent.
                     An example of a dict object would be:
                     ``{"title": "hey Bob!", "body": "you rock"}``
        :type data: str or dict
        :param nonblocking: Whether to block the caller until this method
                            finishes running or not.
        :type nonblocking: bool
        """
        self.sendNotification(
            self.getSubscription(idSession),
            data,
            nonblocking=nonblocking
        )

    @__database__
    def notifyAll(self, data, idGroup=None, exceptList=[], nonblocking=False):
        """
        notifyAll(data, idGroup=None, exceptList=[])
        When no ``idGroup`` is given, notify all subscribers (except for those
        in ``exceptList``). Otherwise, it only notifies all members of the
        ``idGroup`` group (except for those in ``exceptList``).

        :param data: A string or a dict object to be sent.
                     The dict will be automatically converted into a JSON
                     string before being sent.
                     An example of a dict object would be:
                     ``{"title": "hey Bob!", "body": "you rock"}``
        :type data: str or dict
        :param idGroup: an optional Group ID value (0 by default)
        :type idGroup: int
        :param exceptList: The list of sessions ids to be excluded.
        :type exceptList: list
        :param nonblocking: Whether to block the caller until this method
                            finishes running or not.
        :type nonblocking: bool
        """
        condition = " WHERE group_id=" + idGroup if idGroup is not None else ""

        self.sendNotificationToAll(
            [
                row["subscription"]
                for row in self.__db__.execute(
                    "SELECT * FROM subscriptors" + condition
                ).fetchall()
                if row["session_id"] not in exceptList
            ],
            data,
            nonblocking=nonblocking
        )

    @__database__
    def getIdSession(self, subscription):
        """
        getIdSession(subscription)
        Given a subscription object returns the session id associated with it.

        :param subscription: The client's subscription JSON object
        :type subscription: str
        :returns: the session id associated with subscription
        :rtype: str
        """
        res = self.__db__.execute(
            "SELECT session_id FROM subscriptors WHERE subscription=?",
            (subscription,)
        ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getSubscription(self, idSession):
        """
        getSubscription(idSession)
        Given a session id returns the subscription object associated with it.

        :param idSession: A session id
        :type idSession: str
        :returns: The client's subscription JSON object associated with
                  the session id.
        :rtype: str
        """
        res = self.__db__.execute(
            "SELECT subscription FROM subscriptors WHERE session_id=?",
            (idSession,)
        ).fetchone()
        return res.values()[0] if res else None

    @__database__
    def getGroupId(self, idSession):
        """
        getGroupId(idSession)
        Given a session id returns the group id it belongs to.

        :param idSession: A session id
        :type idSession: str
        :returns: a group id value
        :rtype: int
        """
        res = self.__db__.execute(
            "SELECT group_id FROM subscriptors WHERE session_id=?",
            (idSession,)
        ).fetchone()
        return res.values()[0] if res else None
