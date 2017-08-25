/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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

#define uECC_BYTES 32

const struct uECC_Curve_t * curve;

typedef struct keypair {
    uint8_t privkey[uECC_BYTES];
    uint8_t pubkey[uECC_BYTES*2];
    uint8_t* b64_pubkey_short;
} keypair;

unsigned char* aes_gcm_decrypt(unsigned char* cipher_b64,
        unsigned char* shared_secret_b64,
        unsigned char* iv_b64,
        unsigned char* auth_tag_b64) {

    /*
    unsigned char iv_b64[] = "3jm2zJY5Jb3n9y9/";
    unsigned char auth_tag_b64[] = "kFGQHjGuf/VxCoC11sQdOA==";
    unsigned char enc_msg_b64[] = "F5rMvGESdsftkLT8Nw==";
    // deriveSharedSecret from dh keys in msg, later
    unsigned char shared_secret[] = "Qm62tmITFVGytcn3vU2HeA=="; */
    size_t key_len = 0;
    size_t iv_len = 0;
    size_t cipher_len = 0;

    debug_print("%s\n", "Decode b64 fields");
    uint8_t* key = b64_decode_ex(shared_secret_b64, strlen(shared_secret_b64), &key_len);
    unsigned char* iv = b64_decode_ex(iv_b64, strlen(iv_b64), &iv_len);
    unsigned char* cipher = b64_decode_ex(cipher_b64, strlen(cipher_b64), &cipher_len);
    uint8_t* auth_tag = b64_decode(auth_tag_b64, strlen(auth_tag_b64));

    debug_print("Asked to decrypt cipher %s of len %zd key_len %zd \n", cipher_b64, cipher_len, key_len);

    br_aes_ct_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct_ctr_init(&bc, key, key_len);

    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
    br_gcm_reset(&gc, iv, iv_len);
    br_gcm_aad_inject(&gc, auth_tag, 16);
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0, cipher, cipher_len);
    if (br_gcm_check_tag(&gc, auth_tag)) {
        debug_print("%s\n", "bad auth tag");
        return NULL;
    }

    debug_print("Decrypted to %s \n", cipher);
    return cipher;
}

void test_decrypt() {
    unsigned char iv_b64[] = "3jm2zJY5Jb3n9y9/";
    unsigned char auth_tag_b64[] = "kFGQHjGuf/VxCoC11sQdOA==";
    unsigned char cipher_b64[] = "F5rMvGESdsftkLT8Nw==";
    unsigned char shared_secret[_b64] = "Qm62tmITFVGytcn3vU2HeA==";
    unsigned char* cleartext = aes_gcm_decrypt(cipher_b64, shared_secret_b64, iv_b64, auth_tag_b64);
    debug_print("Have cleartedt: %s\n", cleartext);
}

void test_encrypt() {
    unsigned char* message;
    unsigned char* key;
    unsigned char* iv;
    unsigned char tag[16];
    unsigned char* cipher = aes_gcm_encrypt(msg_b64, key_b64, iv_b64, tag);
}

int main() {
    debug_print("%s\n", "Go go go");
    unsigned char json[] = "\"Hello world\"";
    unsigned char shared_secret[] = "Qm62tmITFVGytcn3vU2HeA==";
    unsigned char iv_b64[] = "3jm2zJY5Jb3n9y9/";
    unsigned char tag[16];
    size_t json_len = strlen(json);
    memset(tag, 0, 16);

    size_t key_len = 0;
    size_t iv_len = 0;
    uint8_t* key = b64_decode_ex(shared_secret, strlen(shared_secret), &key_len); // should be 16 bytes
    unsigned char* iv = b64_decode_ex(iv_b64, strlen(iv_b64), &iv_len);

    debug_print("%s\n", "beg innning");
    debug_print("start encrypt key_len %d json_len %zd iv_len %zd\n", key_len, json_len, iv_len);

    br_aes_ct_ctr_keys bc;
    br_aes_ct_ctr_init(&bc, key, key_len);
    debug_print("%s\n", "aes keys inited");

    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
    br_gcm_reset(&gc, iv, iv_len);
    debug_print("%s\n", "Ready after reset");
    //br_gcm_aad_inject(&gc, auth_tag, auth_tag_len);
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, json, json_len);
    br_gcm_get_tag(&gc, tag);

    debug_print("after encryption, json_len is %zd\n", json_len);
    debug_print("json is ecnrypted b64enc %s\n", b64_encode(json, json_len));
}

