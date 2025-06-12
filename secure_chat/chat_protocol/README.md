# Secure Chat Protocol



## Session Establishment

The server awaits 'technical' connections from an incoming client. 
The underlying 'technical' connection is used to establish a `SecureChat` session using an exchange of two messages: 
a `JoinMessage` request message and the server's `WelcomeMessage`.

A session is established only after the `WelcomeMessage` is sent by the server.

### The `JoinMessage`

A client MUST send a `JoinMessage` with his name and signature (sign json message w/o the signature with his private key) right after connection.
Until the client sends this message, the server will not accept any other messages or send any messages to it.
If the client name already exists the server MUST send an `ErrorMessage` with the appropriate error message to the client and disconnect from the client.
if the server does not have the public key for the client name, the server MUST send an `ErrorMessage` with the appropriate error message to the client and disconnect from the client.
The server MUST validate the client signature by opening the signature using the client's public key and compare it to the join message. 
If the client signature is not valid the server MUST send an `ErrorMessage` with the appropriate error message to the client and disconnect from the client.

#### Validating a `JoinMessage`
The server is expected to have a public key in the server's key store for each of the users that are connected to the 
server and a mapping to the name of that particular user. For example, a directory with `<user_name>.pem` files for each user.
The server MUST validate the client signature by opening the signature using the client's public key and compare it to the join message in json format/
If the client signature is not valid the server MUST send an `ErrorMessage` with the appropriate error message to the client and disconnect from the client.

### The `WelcomeMessage`

The client MUST NOT send, nor accept any other messages until it receives the `WelcomeMessage` or an `ErrorMessage` as mentioned above.
The server MUST send a `WelcomeMessage` to the client with the list of users it can communicate with after it gets the `JoinMessage` from the client.
The `WelcomeMessage` MUST contain a list of `UserInfo` objects for all users connected, each of which contains the name of the user and the public key of the user.
Once a user is welcomed, the server MUST send an `AddUserMessage` to all other clients to have them add the user to their list of users.

##  Session Messages

During its lifetime, the server keeps all other sessions updated whenever users join or leave (or disconnects), by 
broadcasting any number of `AddUserMessage` and `RemoveUserMessage` as appropriate.

### The `AddUserMessage`

The server MUST broadcast a `AddUserMessage` for each new user session.
The client MUST add the user in an accepted `RemoveUserMessage` from its list of users.
The client MUST replace the `AddUserMessage` even if the user is already known and update the public key if needed.

### The `RemoveUserMessage`

The server MUST send a `RemoveUserMessage` for each terminated session.
The client MAY ignore `RemoveUserMessage` if the user is not known to him.
The client MUST remove the user in an accepted `RemoveUserMessage` from its list of users.

### The `PrivateMessage` and `RoutedPrivateMessage`

The client MAY send a `PrivateMessage`s and the server MUST route a corresponding `RoutedPrivateMessage` to 
the designate `to_name` user session client, after adding the correct `from_name` to it.

The server MUST reply with an `ErrorMessage` if the user is not known to him.

The receiving client MUST apply its private key on the `encrypted_text` field of `RoutedPrivateMessage` and get the 
message text.
If the decryption fails, the client MUST reply with an `ErrorMessage` to the server.

### The `PublicMessage`and `RoutedPrivateMessage`

The client MAY send a `PublicMessage` and the server MUST broadcast a corresponding `RoutedPublicMessage` to all other 
user sessions, after adding the correct `from_name` to it.

The server MUST reply with an `ErrorMessage` if the user is not known to him.

A receiving client SHOULD reply with an `ErrorMessage` if the user is not known to him.

## Session Termination

A client may send a `LeaveMessage` to the server.
After sending a `LeaveMessage` the client MUST NOT send nor accept any other messages from the server.
The server MUST remove the user from its list of users. 
The server MUST terminate the underlying 'technical' connection with the client.
The server MUST send an appropriate `RemoveUserMessage` to all other sessions.

The server MUST respond with an `ErrorMessage` to any message sent to non-exiting user.


A session can terminate due to 'technical' disconnection or error.

Whenever the underlying 'technical' layer is disconnected or has an error, the server MUST terminate the session and disconnect the client.
When a session is terminated (aas part of the protocol)

as well as planned. 

## Error Messages

When ever an error message is sent in response to the message, it MUST contain the id of the original message.