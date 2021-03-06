#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Sergio Burdisso (sergio.burdisso@gmail.com)

from solidwebpush import Pusher

subscription = '<paste here the subscription object generated after subscribing your serviceWorker(sw.js)>'
# e.g.         '{"endpoint":"https://fcm.googleapis.com/fcm/send/e0rq2RDMkoY:APA91bFEit0f609_b9LVBqDxD_ChUtgtq3iR4Dvzb-dHjLC94uC1oXdd0Fy7Llg9WZ4bnz0TzrBGiYNJ7R701WyCIBS1Rai540fCs4rGpv8kAdvmAYuMOHLh8NIzfVKssHl5N4C0rs_k","keys":{"p256dh":"BAIm1mzWUIz8LY2aknZadJoSZcwKvT2s6qtnJBgzfaPS0wT7xtPacZ2YcH0V5J_5Y8lSGVl6hHEngKWHqX6q5KM=","auth":"qAzORLvbIEvJaIvkIgbKqQ=="}}'

pusher = Pusher(verbose=True)
pusher.sendNotification(subscription, "Hello World")
