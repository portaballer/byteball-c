#ifndef BB_DEVICE_H
#define BB_DEVICE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "byteball_signature.h"

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

#define LOGGED_IN 0x01
#define IS_PAIRED 0x02

typedef struct app_state {
    uint8_t temp_pubkey_counter;
    uint8_t state;
} app_state;

typedef struct paired_peers {
    uint8_t* peer_pairing_secret;
    uint8_t* peer_device_pubkey;
    uint8_t* peer_hub;
} paired_peers;

typedef struct bb_device {
    char* name;
    char* hub;
    keypair* keys;
    keypair* temp_keys;
    uint8_t temp_pubkey_counter;
    uint8_t state;
} bb_device;

/*
 * bb_device struct to initialize, private keys from fileName
 */ 
int init_bb_device(bb_device* device);
int init_bb_device_from_file(bb_device* device, const char* fileName);

#endif /* BB_DEVICE_H */
