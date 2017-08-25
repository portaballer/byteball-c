
## Byteball embedded / IoT

device contains the app-state and keys
signature contains the secp256k1 hashing and aes-gcm-128 utility functions
msgs defines the message requests and handlers
wss contains a shitty websocket implementation (OK-enough-for-embeded-systems)

# Byteball-IoT is built with / depends on

    BearSSL - https://bearssl.org/
    MicroECC - http://kmackay.ca/micro-ecc/
    lwIP with the unix socket interface

    More performance and for smaller systems can be accomplished by going lower
    with lwIP, using the event-based/callback interface.

    BearSSL requires down to 25K memory.
        Note: TLS is not strictly necessary for communication with a hub.
    MicroECC reasonably fast on 3K
    lwIP, configurable to run with rocks and stones

Most of the difficulty porting Byteball to an embedded system is the JSON parsing.
Some of Byteball messages are too big to parse in one go, other solutions have to be
found, such as adapting/requiring JSON messages to be fit for stream-parsing (ie not
alloc the size of the message, but handle it in chunks). Or to let a hub speak MessagePack 
or other smaller data serialization format.

## What for

Act as a Byteball device on an Internet-of-Thing. 

A Byteball device can chat with other devices,
using the Byteball Peer-to-Peer WebSocket network.
The messages are encrypted and signed while in
transport and temporary storage.

Test on ESP8266 (the 12F module) and ESP32 with esp-open-rtos.

- But, what can you do with it?

Chat with your IoT over Byteball, for example to 
ask it for temperature reading or any other sensor,
command your IoT-module to flip LEDs/GPIO pins. Let your
IoT-device pair with a Byteball mechant-bot which can
accept payments from others, in order to flip a light.

Install a few of these LEDs-controlled-by-Byteball-payments
in a public gathering and run an auction for which color
should be displayed by the amount of payments someone is
willing to pay. (Try the better SK6816 rather than WS2812B).

Let love-birds pay for displaying hearts and love-messages,
in a caffe.

You can rework this code so the IoT-module messages its
paired devices events it measures/detects.

You could produce a line of IoT-devices which
all pair with your wallet and understand a set of commands,
such as deliver-data or deliver-keys, effectively
aggregating at the controller-wallet which can trade
access to data.

