#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <cJSON.h>
#include <uECC.h>
#include "b64.h"

#include "bearssl.h"
#include "byteball_device.h"
#include "byteball_signature.h"

/**
 * Fill in device name, make temporary keys in struct.
 * */
int init_bb_device(bb_device* bb_device) {
    return init_bb_device_from_file(bb_device, (const char*)"./ecdsa.priv.3");
}

int init_bb_device_from_file(bb_device* bb_device, const char* fileName) {
    bb_device->name = "iot-devc-";
    bb_device->hub = "wss://byteroll.com/bb";
    load_or_make_keypair(fileName, bb_device->keys);
    load_or_make_keypair("ecdsa.temp.3", bb_device->temp_keys);

    debug_print("\n------bb->name: %s\nbb->hub: %s\nbb->privkey: %s\nbb->b64_pubkey_short: %s\nbb->temp->privkey: %s\nbb->temp_keys->b64_pubkey: %s\n------\n\n",
            bb_device->name, bb_device->hub,
            b64_encode(bb_device->keys->privkey, 32),
            bb_device->keys->b64_pubkey_short,
            b64_encode(bb_device->temp_keys->privkey, 32),
            bb_device->temp_keys->b64_pubkey_short);
    return 0;
}

// int main() {
//     bb_device iot_dev;
//     init_bb_device(&iot_dev);
// }
