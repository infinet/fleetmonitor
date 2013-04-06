
RSA Public Key
==============

peers have each other's public key.

Login into App Engine
=====================

because client and server know each other's public key, and the encryption
method are pre-determined, the login takes only one step.

ClientHello
-----------

the client (reporter on vessel and Google Earth user) generate a 128 bit AES
key for encryption and 256 bit HMAC key for verify message authentication.
These two keys are encrypted by Server's(on App Engine) public key. The clients
use HTTP POST method to send the hello message to login.py.

The format of client hello message is:

RSA encrypted (128 bit AES key + 256 bit HMAC key + random bit) +
AES encrypted (vessel name padding to 20 byte + 28 byte random Pre Master
Secret)

ServerFinish
------------

Upon receive the client hello message, the server first decrypt te AES/HMAC key
using its RSA private key, then use those keys to decrypt aes message. The
server extract the name of the client, which is used to look up the client's
RSA public key. Then the server generate a new AES/HMAC key and a session id.
Those AES/HMAC key and session id will be encrypted with client's RSA public
key and send to the client. The new AES/HMAC key is also used to encrypt the
Pre Master Secret from client. Client will verify this secret to confirm login
successful. These new AES/HMAC key is stored in datastore, use the session id
for key.

The format of server finish message is:

RSA encrypted (keysoup contains new session id, new AES/HMAC key) +
AES encrypted (Pre Master Secret received from client)


AES/HMAC key shared between vessel and GE user
----------------------------------------------

After the pre master secret from server verified, the client generate a new
AES/HMAC key for share between vessel and GE user, this new key soup then
encrypt by GE user's public key, upload to App Engine.

The format of this message:

obfusted session id   16 byte
obfust key            16 byte
AES(
    Request Id           16 byte
    PVIP + vessel name   20 byte
    RSA(new keysoup)
    )

the message also use HTTP POST method post to index.py, which will recover the
session id, use the session id to look up the AES/HMAC key in datastore, then
use that AES/HMAC key to decrypt the message. The keysoup is still protected by
RSA public encryption, it will be store into datastore using vessel name as the
key.

