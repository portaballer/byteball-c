#ifndef BB_SIGNATURE_H
#define BB_SIGNATURE_H

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

/*******************************************************************************
 
Byteball Device
    struct & methods for Signature Key Hash DeEncryption

*******************************************************************************/

/* nifty, https://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing */
#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define debug_print(fmt, ...) \
        do { if (DEBUG_TEST) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

#define FALSE 0
#define TRUE 1

#define BUF_SIZE 4096
#define uECC_BYTES 32

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

const struct uECC_Curve_t * curve;

typedef struct keypair {
    uint8_t privkey[uECC_BYTES];
    uint8_t pubkey[uECC_BYTES*2];
    uint8_t* b64_pubkey_short;
} keypair;

int load_or_make_keypair(const char* fileName, keypair* keys);

void sha256digest(unsigned char* bytes, ssize_t bytes_len, uint8_t* hash);
uint8_t* sha256_ecc_sign(uint8_t* bytes, ssize_t bytes_len, uint8_t* privkey);
uint8_t* ecc_sign(uint8_t* bytes, ssize_t bytes_len, uint8_t* privkey);

uint8_t* encryptPackage(uint8_t* json, uint8_t* recipient_device_pubkey);

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    br_sha256_context ctx;
} SHA256_HashContext;

static void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    br_sha256_init(&context->ctx);
}

static void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    br_sha256_update(&context->ctx, message, message_size);
}

static void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    br_sha256_out(&context->ctx, hash_result);
}

#endif /* BB_SIGNATURE_H */

