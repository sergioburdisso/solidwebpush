#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Sergio Burdisso (sergio.burdisso@gmail.com)

from solidwebpush import Pusher

pusher = Pusher()

#Use one of these for subscribing
#your serviceWorker in your client.

#1) This one, if you will decode it using a function
#   like the "urlB64ToUint8Array" from 
#   https://codelabs.developers.google.com/codelabs/push-notifications#4
print "Base64-Urlsafe Public Key:"
print pusher.getUrlB64PublicKey()


print "======"

#2) or, this one, if you just want to use the
#   built-in Javascript function "atob" to
#   decode it.
print "Base64 Public Key:"
print pusher.getUrlB64PublicKey()
