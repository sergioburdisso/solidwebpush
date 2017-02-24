#!/usr/bin/python
# -*- coding: utf-8 -*-

from solidwebpush import Pusher

subscriptionInfo = '<paste here the subscription-JSON object generated after subscribing your serviceWorker(sw.js)>'

msg = {
    "type": "warn",
    "title": "Temperatura alta",
    "body": "La CPU se encuentra a %.1f°C" % 61.4
}

pusher = Pusher()

pusher.sendNotification(subscriptionInfo, msg)


#pusher.newSubscription("pepe", subscriptionInfo)
#pusher.notify("pepe", msg)
#pusher.notifyAll(msg)

raw_input()