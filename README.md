# blatherskite
> blath·er·skite ⬩ 
> /ˈblaT͟Hərˌskīt/
>    - a person who talks at great length without making much sense.
>    - foolish talk; nonsense.

# Dependencies
You'll need to install CassandraDB for this: you can do that by running:
```
brew install cassandra
```

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

## Scuttlebutt
Scuttlebutt is an HTTP service that handles the creation, deletion, and updating of groups/channels/users as well as misc others.

The various methods and objects are documented at `localhost:3000`, and the basic usage flow is something like:
- `POST /api/user` to make a user, which will return a User object (see Schemas on the docs)
- `GET /api/login` to login with said user. This will return a JWT that you'll use to authenticate future requests. This token will expire in a day!
- Whatever requests you'd like at that point! Authenticate by including a `ScuttleKey` header with the token you got.

## Chatterbox
Chatterbox is a websocket service used for sending and receiving messages. To use:
- Connect to the websocket at `ws://localhost:3001/ws/whee`
- Send authentication in the form of `{"hash": "YOUR_PASSWORD_HASH", "id": "YOUR_ID"}`
- Then use the websocket as normal!
  - Send message requests in the form of `{"content": "whee", "channel": "CHANNEL_ID"}`
  - Recieve messages!
