# -*- coding: utf-8 -*-
"""
This module lets your server send Web Push Notifications to your clients.

(Please, visit https://github.com/sergioburdisso/solidwebpush for more info).

----
"""
from __future__ import print_function
from sqlite3 import connect as db_connect
from multiprocessing import Pool
from py_vapid import Vapid

import os
import re
import json
import time
import base64
import requests
import http_ece
import pyelliptic


__version__ = '1.2.3'
__license__ = 'MIT'


def __doc_from__(docfunc):
    """A @decorator."""
    def __wrapper__(func):
        func.__name__ = docfunc.__name__
        func.__doc__ = docfunc.__doc__
        return func
    return __wrapper__


def __database__(func):
    """A @decorator."""
    @__doc_from__(func)
    def __init_database__(*args, **kwargs):
        s = args[0]

        if not s.__db_conn__:
            s.__db_conn__ = db_connect(s.__db_name__)
            s.__db_conn__.row_factory = lambda cursor, row: \
                dict((
                    (col[0], row[idx])
                    for idx, col
                    in enumerate(cursor.description)
                ))
            s.__db__ = s.__db_conn__.cursor()

            try:
                s.__db__.executescript('''
                    CREATE TABLE subscriptors (
                        session_id VARCHAR(256) NOT NULL PRIMARY KEY,
                        subscription VARCHAR(512) NOT NULL,
                        group_id INT NOT NULL
                    );
                ''')
                s.__db_conn__.commit()
            except:
                pass

            result = func(*args, **kwargs)

            s.__db_conn__.close()
            s.__db_conn__ = None
        else:
            result = func(*args, **kwargs)

        return result

    __init_database__.__name__ = func.__name__
    __init_database__.__doc__ = func.__doc__

    return __init_database__


def __is_valid_json__(jstr):
    try:
        json.loads(jstr)
        return True
    except:
        return False


class SesionIDError(Exception):
    """ exception to be thrown when no proper session_id is used """
    def __init__(self, message):
        Exception.__init__(self, message)


class SubscriptionError(Exception):
    """ exception to be thrown when no proper subscription is used """
    def __init__(self, msg=''):
        Exception.__init__(
            self,
            "subscription must be a valid JSON str, bytes or bytearray."
        )


class Pusher:
    """
    Pusher objects allows you to integrate Web Push Notifications
    into your project.

    Instantiate this class to integrate Web Push Notifications
    into your server. Objects of this class will create your public
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

    __db_name__ = None
    __db_conn__ = None
    __db__ = None
    __pool__ = None

    __RE_URL__ = r"(https?://(?:[\w-]+\.)*[\w-]+(?::\d+)?)(?:/.*)?"

    def __init__(self, db_name="subscriptors.db", verbose=False):
        """
        Class constructor.

        :param db_name: The [optional] name ("subscriptors.db" by default) of
                       the file in which subscriptions will be stored in.
                       This is only required if methods like
                       ``newSubscription`` will be used.
        :type db_name: str
        :param verbose: An optional value, to enabled or disabled the "verbose
                        mode" (False by default)
        :type verbose: bool
        """
        self.__verbose__ = verbose
        self.__db_name__ = db_name

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
        """Class state getter."""
        self_dict = self.__dict__.copy()
        try:
            del self_dict['__pool__']
            del self_dict['__db_conn__']
            del self_dict['__db__']
        except KeyError:
            pass
        return self_dict

    def __call__(self, subscription, data):
        """Class instances callable."""
        self.__send__(subscription, data)

    def __print__(self, msg):
        """Verbose print wrapper."""
        print("[ SolidWebPush ] %s" % msg)

    def __b64rpad__(self, b64str):
        """Base64 right (=)padding."""
        return b64str + b"===="[:len(b64str) % 4]

    def __encrypt__(self, user_publickey, user_auth, payload):
        """Encrypt the given payload."""

        user_publickey = user_publickey.encode("utf8")
        raw_user_publickey = base64.urlsafe_b64decode(
            self.__b64rpad__(user_publickey)
        )

        user_auth = user_auth.encode("utf8")
        raw_user_auth = base64.urlsafe_b64decode(self.__b64rpad__(user_auth))

        salt = os.urandom(16)

        curve = pyelliptic.ECC(curve="prime256v1")
        curve_id = base64.urlsafe_b64encode(curve.get_pubkey()[1:])

        http_ece.keys[curve_id] = curve
        http_ece.labels[curve_id] = "P-256"

        encrypted = http_ece.encrypt(
            payload.encode('utf8'),
            keyid=curve_id,
            dh=raw_user_publickey,
            salt=salt,
            authSecret=raw_user_auth,
            version="aesgcm"
        )

        return {
            'dh': base64.urlsafe_b64encode(
                curve.get_pubkey()
            ).strip(b'=').decode("utf-8"),
            'salt': base64.urlsafe_b64encode(
                salt
            ).strip(b'=').decode("utf-8"),
            'body': encrypted
        }

    def __send__(self, subscription, data):
        """Encrypt and send the data to the Message Server."""
        if __is_valid_json__(subscription):
            subscription = json.loads(subscription)
        else:
            raise SubscriptionError()

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

        jwt_payload = {
            "aud": base_url,
            "exp": str(int(time.time()) + 60 * 60 * 12),
            "sub": "mailto:admin@mail.com"
        }

        headers = self.__vapid__.sign(jwt_payload)
        headers["TTL"] = str(43200)
        headers["Content-Type"] = "application/octet-stream"
        headers['Content-Encoding'] = "aesgcm"
        headers['Encryption'] = "salt=%s" % encrypted["salt"]
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
        Verbose mode.

        Enable and disable the verbose mode (disabled by default).
        When verbose mode is active, some internal messages are going
        to be displayed, as well as the responses from the Message Server.

        :param value: True to enable or False to disable
        :type value: bool
        """
        self.__verbose__ = value

    def getPublicKey(self):
        """
        Raw public key getter.

        :returns: the raw public key
        :rtype: str
        """
        return b"\x04" + self.__vapid__.public_key.to_string()

    def getPrivateKey(self):
        """
        Raw private key getter.

        (probably you won't care about private key at all)

        :returns: the raw private key
        :rtype: str
        """
        return self.__vapid__.private_key.to_string()

    def getB64PublicKey(self):
        """
        Base64 public key getter.

        Returns the string you're going to use when subscribing your
        serviceWorker.
        (as long as you're planning to decode it using JavaScript's
        ``atob`` function)

        :returns: Base64-encoded version of the public key
        :rtype: str
        """
        return base64.b64encode(self.getPublicKey()).decode("utf-8")

    def getB64PrivateKey(self):
        """
        Base64 private key getter.

        (probably you won't care about private key at all)

        :returns: Base64-encoded version of the private key
        :rtype: str
        """
        return base64.b64encode(self.getPrivateKey()).decode("utf-8")

    def getUrlB64PublicKey(self):
        """
        Url-Safe Base64 public key getter.

        This is the string you're going to use when subscribing your
        serviceWorker.
        (so long as you're planning to decode it using a function like
        ``urlB64ToUint8Array`` from
        https://developers.google.com/web/fundamentals/getting-started/codelabs/push-notifications/)

        :returns: URLSafe-Base64-encoded version of the public key
        :rtype: str
        """
        return base64.urlsafe_b64encode(
            self.getPublicKey()
        ).strip(b"=").decode("utf-8")

    def getUrlB64PrivateKey(self):
        """
        Url-Safe Base64 private key getter.

        (probably you won't care about private key at all)

        :returns: URLSafe-Base64-encoded version of the private key
        :rtype: str
        """
        return base64.urlsafe_b64encode(
            self.getPrivateKey()
        ).strip(b"=").decode("utf-8")

    def sendNotification(self, subscription, data, nonblocking=False):
        """
        Send the data to the Message Server.

        Pushes a notification carrying ``data`` to
        the client associated with the ``subscription`` object.
        If ``nonblocking`` is True, the program won't block waiting
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
        Send the data to the Message Server.

        Pushes a notification carrying ``data`` to
        each of the clients associated with the list of ``subscriptions``.
        If ``nonblocking`` is True, the program won't block waiting
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
        Wait for all the messages to be completely sent.

        Block the program and wait for all the notifications to be sent,
        before continuing.
        This only works if there exist a previous call to a method
        with the ``nonblocking`` parameter set to ``True``,
        as shown in the following example:

        >>> pusher.sendNotificationToAll(
            listOfsubscriptions,
            "Hello World",
            nonblocking=True
        )
        >>> # Maybe some other useful computation here
        >>> pusher.wait()
        """
        self.__pool__.close()
        self.__pool__.join()
        self.__pool__ = None

    @__database__
    def newSubscription(self, session_id, subscription, group_id=0):
        """
        newSubscription(session_id, subscription, group_id=0)
        Permanently subscribe a client.

        Subscribes the client by permanently storing its ``subscription`` and
        group id (``group_id``).
        This will allow you to push notifications using the
        client id (``session_id``) instead of its ``subscription`` object.

        Groups help you organize subscribers. For instance, suppose you
        want to notify Bob by sending a notification to all of his devices.
        If you previously subscribed each one of his devices to the same group
        let's say 13, then calling notifyAll with 13 will push notifications to
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

        :param session_id: The client's identification
                          (e.g. a cookie or other session token)
        :type session_id: str
        :param subscription: The client's subscription JSON object
        :type subscription: str
        :param group_id: an optional Group ID value (0 by default)
        :type group_id: int
        """
        if not __is_valid_json__(subscription):
            raise SubscriptionError()
        if not session_id and session_id != 0:
            raise SesionIDError("session_id cannot be empty")

        if not self.getSubscription(session_id):
            old_session_id = self.getIdSession(subscription)
            if old_session_id:
                self.removeSubscription(old_session_id)
            self.__db__.execute(
                "INSERT INTO subscriptors (session_id, subscription, group_id)"
                " VALUES (?,?,?)",
                (session_id, subscription, group_id)
            )
        else:
            self.__db__.execute(
                "UPDATE subscriptors SET subscription=?, group_id=? WHERE"
                " session_id=?",
                (subscription, group_id, session_id,)
            )
        self.__db_conn__.commit()

    @__database__
    def removeSubscription(self, session_id):
        """
        removeSubscription(session_id)
        Permanently unsubscribes a client.

        Unsubscribes the client by permanently removing its ``subscription``
        and group id.

        :param session_id: The client's identification (e.g. a cookie or other
                          session token)
        :type session_id: str
        """
        self.__db__.execute(
            "DELETE FROM subscriptors WHERE session_id = ?",
            (session_id,)
        )
        self.__db_conn__.commit()

    @__database__
    def notify(self, session_id, data, nonblocking=False):
        """
        notify(session_id, data, nonblocking=False)
        Notify a given client.

        Pushes a notification carrying ``data`` to the client associated with
        the ``session_id``.
        ``session_id`` is the value passed to the ``newSubscription`` method
        when storing the client's subscription object.

        :param session_id: The client's identification (e.g. a cookie or other
                          session token)
        :type session_id: str
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
        if self.getSubscription(session_id):
            self.sendNotification(
                self.getSubscription(session_id),
                data,
                nonblocking=nonblocking
            )
        else:
            raise SesionIDError(
                "the given session_id '%s' does not exist "
                "(it has not been subscribed yet)." % session_id
            )

    @__database__
    def notifyAll(self, data, group_id=None, exceptions=[], nonblocking=False):
        """
        notifyAll(data, group_id=None, exceptions=[], nonblocking=False)
        Notify a group of clients.

        When no ``group_id`` is given, notify all subscribers (except for those
        in ``exceptions``). Otherwise, it only notifies all members of the
        ``group_id`` group (except for those in ``exceptions``).

        :param data: A string or a dict object to be sent.
                     The dict will be automatically converted into a JSON
                     string before being sent.
                     An example of a dict object would be:
                     ``{"title": "hey Bob!", "body": "you rock"}``
        :type data: str or dict
        :param group_id: an optional Group ID value (0 by default)
        :type group_id: int
        :param exceptions: The list of sessions ids to be excluded.
        :type exceptions: list
        :param nonblocking: Whether to block the caller until this method
                            finishes running or not.
        :type nonblocking: bool
        """
        if group_id is not None:
            condition = " WHERE group_id=" + group_id
        else:
            condition = ""

        self.sendNotificationToAll(
            [
                row["subscription"]
                for row in self.__db__.execute(
                    "SELECT * FROM subscriptors" + condition
                ).fetchall()
                if row["session_id"] not in exceptions
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
        return list(res.values())[0] if res else None

    @__database__
    def getSubscription(self, session_id):
        """
        getSubscription(session_id)
        Given a session id returns the subscription object associated with it.

        :param session_id: A session id
        :type session_id: str
        :returns: The client's subscription JSON object associated with
                  the session id.
        :rtype: str
        """
        res = self.__db__.execute(
            "SELECT subscription FROM subscriptors WHERE session_id=?",
            (session_id,)
        ).fetchone()
        return list(res.values())[0] if res else None

    @__database__
    def getGroupId(self, session_id):
        """
        getGroupId(session_id)
        Given a session id returns the group id it belongs to.

        :param session_id: A session id
        :type session_id: str
        :returns: a group id value
        :rtype: int
        """
        res = self.__db__.execute(
            "SELECT group_id FROM subscriptors WHERE session_id=?",
            (session_id,)
        ).fetchone()
        return list(res.values())[0] if res else None
