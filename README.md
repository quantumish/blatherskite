# blatherskite
> blath·er·skite ⬩ 
> /ˈblaT͟Hərˌskīt/
>    - a person who talks at great length without making much sense.
>    - foolish talk; nonsense.

# About
`blatherskite` is a drop-in chat backend for your messaging app. 

# Dependencies
You'll need to install CassandraDB for this: you can do that by running:
```
brew install cassandra
```

> **Warning**
> This is a little wonky on M1 Macs: you'll need to follow the advice of [this page](https://stackoverflow.com/questions/69486339/nativelibrarydarwin-java64-failed-to-link-the-c-library-against-jna-native-m) when you face the inevitable JNA link error. Download for more recent JNA version is [here](https://search.maven.org/artifact/net.java.dev.jna/jna/5.8.0/jar). I personally ran `sudo mv jna-5.8.0.jar /opt/homebrew/Cellar/cassandra/4.0.6/libexec/jna-5.6.0.jar` (I think...) once I downloaded the new version, and that fixed it.


You also need to install the Rust language: 
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

# Usage 
Start by launching the database in the background with 
```
cassandra -f
```
Then, launch `chatterbox` - the service for sending/getting messages - and `scuttlebutt` - the service for everything else. 
```
cargo run -p chatterbox & 
cargo run -p scuttlebutt &
```

## Features
Beyond basic text messaging, `blatherskite` has support for: 
- Discord-esque servers
- Threads
- Direct messages
- Basic permissioning (owner/admin/none)

### Terminology
Here's a quick guide to to the terms used by the service (that you might see in the `scuttlebutt` documentation):

- Users can create or be invited to *groups* which contain *channels*.
- Groups have:
  - *members*, the users who are part of the group
  - an *owner*, who made the group and is permitted to do specific actions (like deleting it)
  - *admin*, users who have elevated permissions for a group (like adding/removing channels)
- *DMs* are a special kind of group that are made between users directly and limit certain functionality. DMs only have one channel and have no admin.
- Channels also have *members* (which can be a subset of the group!). Channels by default are *public*, which means when a user is invited to a group they will be added to the channel. You can set them to *private* with another API call.

## Scuttlebutt
Scuttlebutt is an HTTP service that handles the creation, deletion, and updating of groups/channels/users as well as misc other actions.

The various methods and objects are documented at `localhost:3000`, and the basic usage flow is something like:
- `POST /api/user` to make a user, which will return a User object (see Schemas on the docs)
- `GET /api/login` to login with said user. This will return a JWT that you'll use to authenticate future requests. This token will expire in a day!
- Whatever requests you'd like at that point! Authenticate by including a `ScuttleKey` header with the token you got.

## Chatterbox
Chatterbox is a websocket service used for sending and receiving messages. To use:
- Connect to the websocket at `ws://localhost:3001/`
- Send authentication in the form of `{"hash": "YOUR_PASSWORD_HASH", "id": "YOUR_ID"}`
- Then use the websocket as normal!
  - Send message requests in the form of `{"content": "whee", "channel": "CHANNEL_ID"}`
  - Recieve messages!
