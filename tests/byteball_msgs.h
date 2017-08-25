#ifndef BB_MSGS_H
#define BB_MSGS_h

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <cJSON.h>

#include "byteball_device.h"

/*********************************************************

  Byeball messages with cJSON
  And a few handlers

**********************************************************/

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

/*
 * a justsaying subject handler should be given and return cJSON
 * messages of type justsaying dont need to hold converstaion state
 * */
struct subject_action {
    char* str;
    cJSON* (*func)(cJSON* json);
};

bb_device iot_dev;

// these are state-less
int hub_login();
int parse_hub_challenge();
cJSON* version(cJSON* root);
cJSON* hub_challenge(cJSON* json);
cJSON* hub_message(cJSON* json);
cJSON* hub_message_box_status(cJSON* json);
cJSON* hub_push_project_number(cJSON* json);
//cJSON* subscribe(cJSON* json);
cJSON* info(cJSON* json);
cJSON* rotate_temp_pubkey();

cJSON* subscribe(cJSON* json, char* tag);

// requests need to keep at least the tag
/* request and response, unlike justsaying, has to keep state of conversation, justsayin
 * is gossip and doesnt need state.
 * */

/* not justsaying, but is request from iot, like ["request", {}]
 * # -- in implementation order
 * hub/temp_pubkey // update our temp pubkey
 * hub/get_temp_pubkey // from correspondent
 * hub/deliver
 * hub/delete
 * hub/refresh // downloads new msgs?
 *
 * heartbeat
 * subscribe
 * get_witnesses
 * light/get_history
 * light/have_updates
 * light/get_link_proofs
 * light/get_parents_and_last_ball_and_witness_list_unit
 * */

#endif /* BB_MSGS_H */
