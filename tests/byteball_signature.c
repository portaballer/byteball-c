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
#include "byteball_signature.h"

/*******************************************************************************
 
Byteball Device
    struct & methods for Signature Key Hash DeEncryption

*******************************************************************************/

#define BUF_SIZE 4096
#define uECC_BYTES 32

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

void sha256digest(unsigned char* bytes, ssize_t bytes_len, uint8_t* hash) {
    br_sha256_context sc;
    br_sha256_init(&sc);
    br_sha256_update(&sc, bytes, bytes_len);
    br_sha256_out(&sc, hash);
}

uint8_t* sha256_ecc_sign(uint8_t* bytes, ssize_t bytes_len, uint8_t* privkey) {
    uint8_t hash[32];
    memset(hash, 0, 32);
    sha256digest((unsigned char*)bytes, bytes_len, hash);
    debug_print("Hash, but in base64 to sign is \n[ %s ] \n", b64_encode(hash, 32));
    return ecc_sign(hash, bytes_len, privkey);
}

uint8_t* ecc_sign(uint8_t* hash, ssize_t bytes_len, uint8_t* privkey) {
    uint8_t* signature;
    signature = malloc(uECC_BYTES*2); // 64
    if (signature == NULL) {
        debug_print("%s\n", "ERROR out of mem cannot allocate");
        return NULL;
    }
    memset(signature, 0, uECC_BYTES*2);
    uint8_t result_sz = 32;
    uint8_t block_sz = 64;
    uint8_t tmp[2 * result_sz + block_sz];
    SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256,
        block_sz, result_sz, tmp}};

    memset(signature, 0, 64);
    debug_print("Private key size %d\n", uECC_curve_private_key_size(curve));
    if (!uECC_sign_deterministic(privkey, hash, 32, &ctx.uECC, signature, curve)) {
        printf("%s\n", "ERROR ecc_sign_deterministic failed");
        return;
    }

    printf("Signature is:\n[ %s ]\n", b64_encode(signature, 64));

    // if (!uECC_verify(public1, hash, 32, signature, curve)) {
    //     debug_print("%s\n", "uECC_verify failed");
    // } else {
    //     debug_print("%s\n", "uECC_verify signature is good");
    // }
    return signature;
}

/**
 * Read a private key from a file as bytes, all 32 of them in
 * little endian order to provided buf, compute public key.
 *
 * return 0 on success, anything else is fail.
 * */
int load_or_make_keypair(const char* fileName, keypair* keys) {
    FILE* privkey_fd;
    ssize_t ret_in;
    uint8_t pubkey_short[33];
    curve = uECC_secp256k1();

    privkey_fd = fopen(fileName, "ab+");
    if (privkey_fd) {
        debug_print("Read keys from: %s each item of size %d with amount %d\n", fileName, (int)sizeof(uint8_t), uECC_BYTES);

        ret_in = fread(keys->privkey, sizeof(uint8_t), uECC_BYTES, privkey_fd);
        debug_print("Private-key from file in base64 is %s\n", b64_encode(keys->privkey, uECC_BYTES));

        if (keys->privkey[0] != 0 || ret_in == uECC_BYTES) {
            debug_print("%s\n", "Compute public key");
            uECC_compute_public_key(keys->privkey, keys->pubkey, curve);
            if (uECC_valid_public_key(keys->pubkey, curve) != 1) {
                debug_print("%s\n", "ERROR computed an invalid public key!?");
                return 3;
            }
            debug_print("Computed public key %s\n", b64_encode(keys->pubkey, uECC_BYTES*2));
            uECC_compress(keys->pubkey, pubkey_short, curve);
        } else {
            debug_print("%s\n", "Making new key-pair\n");
            uECC_make_key(keys->pubkey, keys->privkey, curve);
            debug_print("%s %s\n","Saving private-key to file\n", fileName);

            int written;
            FILE* fp = fopen(fileName, "wb"); // truncate
            if (!fp) {
                debug_print("%s\n", "fopen could not truncate");
                return 1;
            }
            written = fwrite(&keys->privkey, 1, uECC_BYTES, privkey_fd);
            if (written != uECC_BYTES) {
                debug_print("%s\n", "Filer-write, could not persist private key");
                return 1;
            }
            uECC_compress(keys->pubkey, pubkey_short, curve); // compress new public
        }

        keys->b64_pubkey_short = b64_encode(pubkey_short, uECC_BYTES+1);
        debug_print("Have private:\n\t[ %s ]\nand public (short):\n\t[ %s ]\n\n",
                    b64_encode(keys->privkey, uECC_BYTES), keys->b64_pubkey_short);
    }

    fclose(privkey_fd);
    return 0;
}

uint8_t* encryptPackage(uint8_t* json, uint8_t* recipient_device_pubkey) {
    // json stringified
    keypair sender_ephemeral;
    uECC_make_key(sender_ephemeral.pubkey, sender_ephemeral.privkey, curve);
    uint8_t secret[32];
    uint8_t secret_hash[32];
    //uECC_shared_secret(recipient_device_pubkey, iot_dev.keys->privkey, secret, curve);
    sha256digest(secret, 32, secret_hash); // todo maybe it oly takes first 16 hash bytes
    //uint8_t iv[] = giveRandom(12);
    // set iv
    // 128 bit

    // process json with ciper.update in chunks of 2003
    // and concat then base64 all of it as encmsg
    // cipher.getAuthTag
    // encryptedPackage encmsg b64_encode(iv) b64_encode(auth_tag)
    //      dh: sender_ephemeral_pubkey, recipient_ephemeral_pubkey: recipient_device_pubkey
    // now it can go on wire
}
