
# Solid Web Push

This package lets your server send Web Push Notifications to your clients.
NOTE: **No** particular Web framework are required (e.g. Django, Flask, Pyramid, etc.), since
it was originally designed to run on a Raspberry Pi with no web server installed (
only a bare Python script listening on a port for HTTP requests).

---
## 1. Installation

### 1.1 Using pip

````
sudo pip install solidwebpush
````

### 1.2. Manual installation (recomended for Raspberry Pi)

1. Download this repository
2. Copy the "solidwebpush" folder (the one with the `_init_.py` in it)
3. Paste it into your project folder. NOTE: it has to be the folder in which you have the python script that will `import solidwebpush`.
4. Install the required packages; open the terminal and write:
````
sudo pip install ecdsa
sudo pip install python-jose
sudo pip install http_ece
sudo pip install pyelliptic
sudo pip install py-vapid
````
**Note:** In case of an error, specially if you're on **Raspbian**, try installing these packages before trying again (it worked for me!):
````
sudo apt-get install python-crypto
sudo apt-get install python-cryptography
````

And that's it, you're ready to go, buddy! :D

---
## 2. API Documentation

[http://pythonhosted.org/solidwebpush/](http://pythonhosted.org/solidwebpush/)

---
## 3. "Hello World" Example

In order for us to be able to send a "Hello World" notification from our server to our client devices, we should have the client-side all set up, and that's why first we need to do [this Google codelab](https://developers.google.com/web/fundamentals/getting-started/codelabs/push-notifications/) before we move forward _(Note: if you're already familiar with Web Push Notifications, you could just skip this part; otherwise,  don't have to worry! it shouldn't take you too much time to get it done, trust me :D )_.

Assuming you have finished the [codelab](https://developers.google.com/web/fundamentals/getting-started/codelabs/push-notifications/), the first thing we need to do is to **generate** our own **server public key** so we can subscribe our serviceWorker(_sw.js_) in the client devices. But don't worry, _solidwebpush_ automatically does this for us when we create a `Pusher` object, which is the one we'll use later to notify our clients:

````python
from solidwebpush import Pusher

# This will automatically create a Public key for you
# and store it in a .PEM file. Note: the next time the 
# key won't be created and the value stored in the .PEM
# file will be used instead.
pusher = Pusher()
# And then, let's get our Public Key ...
print pusher.getUrlB64PublicKey() #... as a UrlSafe-Base64-encoded string
````

  
Copy this string and paste it into the _**main.js**_ file:
````javascript
//main.js (line 24)
const applicationServerPublicKey = '<Your Public Key>';
````


And finally, suppouse one of our clients, after registering and subscribing its serviceWorker(_sw.js_), has sent us the following subscription object:

````text
{"endpoint":"https://fcm.googleapis.com/fcm/send/cOZ80twUe2I:APA91bFWFWTIJzD3B7YHCBKzpSD_KfFe5a_XOo0gZDhGX1JYBwtY6UtNVyCXVt0Z2Fd4iOb9SLSOo1WGBclMaWoDFYMcmh7EhlXd-OJXpWK-gAph0cO1OQPrIqCQ_W0C-XJ0fUsqpXU_","keys":{"p256dh":"BMb7ie9TlYqIUcA52gQBXqKFleWoqHnXPOkvlgKGd2Mw4nnEMhII7VwB41xp0T70VrZb0w4LoP4Cn7ccD0zEtmA=","auth":"EKID_2FLZ4uJg6zSHB4psA=="}}
````

And we want to send him a "Hello World" notification, this could be easily done as follows:

````python
from solidwebpush import Pusher

subscription = '{"endpoint":"https://fcm.googleapis.com/fcm/send/cOZ80twUe2I:APA91bFWFWTIJzD3B7YHCBKzpSD_KfFe5a_XOo0gZDhGX1JYBwtY6UtNVyCXVt0Z2Fd4iOb9SLSOo1WGBclMaWoDFYMcmh7EhlXd-OJXpWK-gAph0cO1OQPrIqCQ_W0C-XJ0fUsqpXU_","keys":{"p256dh":"BMb7ie9TlYqIUcA52gQBXqKFleWoqHnXPOkvlgKGd2Mw4nnEMhII7VwB41xp0T70VrZb0w4LoP4Cn7ccD0zEtmA=","auth":"EKID_2FLZ4uJg6zSHB4psA=="}}'

pusher = Pusher()
pusher.sendNotification(subscription, "Hello World")

````
cool, uh?


**Note:** these and more [examples](https://github.com/sergioburdisso/solidwebpush/tree/master/examples) can be found inside the _"examples"_ folder.



---
## 4. Good to know...

In the "real world", subscription objects are going to be sent to our server via HTTP requests (probably using AJAX), and they will be stored along with the user session ID so that, later, when we need to notify a client, we do so by his session id (and not his subscription object). Fortunately, _solidwebpush_ also does this for us, as shown in the following example:

````python
# SERVER CODE
...
from solidwebpush import Pusher
...

pusher = Pusher()

#Note: assuming messages are being sent via HTTP POST
#      and the session token (session_id)  is  stored
#      as a cookie in the client's device.
... 
elif POST["action"] == "subscribe":
    pusher.newSubscription(
        COOKIE["session_id"],
        POST["subscription"]
    )
elif POST["action"] == "unsubscribe":
    pusher.removeSubscription(
        COOKIE["session_id"]
    )
...

# it's worth noting that you can also
# send a dict object instead of a string.
# solidwebpush will convert it into a 
# JSON string before pushing the notification.
msg = {
    "title": "Notification Title",
    "body": "Hello World"
}
#notifying user X
pusher.notify(user_X_session_id, msg)

#or if you want to,
#notify all users
pusher.notifyAll(msg)

...
````
When `Pusher`'s `newSubscription` is called for the very first time, a sqlite-database file will be automatically generated ('subscriptors.db' by default) to store all these subscriptions for us. Later, when we use a method like `notifyAll` (or `notify`), _solidwebpush_ will push the notifications using the information that is stored there.

Finally, I highly recommend you to read the [documentation](http://pythonhosted.org/solidwebpush/) for a "more in depth" understanding of the package. For instance, `newSubscription` and `notifyAll` can receive an [optional] parameter to specify a group ID. As shown below:

````python
...
#new subscription for <session_id>, which belongs to "group 13"
pusher.newSubscription(session_id, subscription, 13)

...
#notifay all members of "group 13"
pusher.notifyAll("Hello World", 13)
...
````

Additionally every method that lets you push notifications (`sendNotification`, `sendNotificationToAll`, `notify`, `notifyAll`) has an [optional] `nonblocking` parameter, in case you want to use a non-blocking version of it. In which case the `wait` method can be called every time you need your program to block until all the messages are sent. For example:

````python
subscriptions = [ ... ]
...
pusher.sendNotificationToAll(subscriptions, "Hello World", nonblocking=True)
# lets continue doing useful things for the user
...

#and in case we need to wait for those messages to be sent
pusher.wait()
````

Why could be a non-blocking version desirable? When blocking mode is used (the default), the server's "main loop" blocks every time it sends notifications and in some cases that is not desirable —for instance, if it negatively affects the overall system response time.