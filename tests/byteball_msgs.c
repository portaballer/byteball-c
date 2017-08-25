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

#include "byteball_msgs.h"
#include "byteball_signature.h"


/*********************************************************

  Byeball messages with cJSON
  And a few handlers

**********************************************************/

// TODO
// 1. DONE a function pointer handler for wsOnOpen nand wsOnMessage
// 2. DONE then modify this main to run_wss by parameters
// 3. DONE implement: version - hub/login hub/challenge respond
// 4. byteball_signature use iot_dev encryptPackage with aes_gcm_128
// 5. pair with other light wallet, encrypt/decrypt msgs
// 7. exchange messages predefined bot commands
// 8. compile with esp-open-rtos, modify Makefile / buildsystem
// 9. subscribe/generate addresses, light/get_history

/*
 * a justsaying subject handler should be given and return cJSON
 * messages of type justsaying dont need to hold converstaion state
 * */

// register justsaying subject map of handlers
struct subject_action handlers [] = {
    { "version", version },
    { "hub/challenge", hub_challenge },
    { "hub/message_box_status", hub_message_box_status }, // {"subject":"hub/message_box_status","body":"empty"}
    { "info", info },
    { "hub/push_project_number", hub_push_project_number } // {projectNumber: conf.pushApiProjectNumber} logged-in
    /*
    { "hub/message", hub_message }, // read message
    { "subscribe", subscribe }
    */
};
cJSON* req_subscribe(cJSON* json, cJSON* tag);

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

uint8_t recursed = 0;
void onMessage(br_sslio_context* ioc, uint8_t* message, uint16_t len) {
    uint16_t msg_len = strnlen((const char*)message, len);
    debug_print("msg_len %d len %d\n", msg_len, len);
    onBBMessage(ioc, message, msg_len);
}

cJSON* handle_justsaying(cJSON* second_item) {
    cJSON *subject_ob = cJSON_GetObjectItemCaseSensitive(second_item, "subject");
    if (cJSON_GetErrorPtr() == 0) {
        debug_print("%s\n", "a justsaying subject");
        char* subject = cJSON_Print(subject_ob);
        if (strnlen(subject, 128) < 2) {
            debug_print("%s\n", "Some kind of schenanigans");
            return;
        }
        debug_print("subject %s, \n\n", subject);
    
        // invoke justsaying subject handlers as per defined mapping
        struct subject_action* action = handlers;
        uint16_t handlers_len = sizeof(handlers) / sizeof(handlers[0]);
        debug_print("size of handlers %d\n", handlers_len);
        for (uint8_t i = 0; i < handlers_len; i++, action++) {
            debug_print("Handling subject %s %s\n", action->str, subject);
            if (0 == strncmp(action->str, &subject[1], strlen(subject)-2)) {
                debug_print("%s\n", "calling the func");
                return (*action->func)(second_item);
            }
        }
    }
    return NULL;
}

uint16_t write_all_flush(br_sslio_context* ioc, uint8_t message, uint16_t len) {
    // mock only
}

uint8_t* initiate_pairing() {
    cJSON *array;
    cJSON *body;
    cJSON *body_obj;
    make_pairing_message();
    return cJSON_Print(array);
}

void onBBMessage(br_sslio_context* ioc, uint8_t* message, uint16_t len) {
    debug_print("HANDLING message: %s\n", message);
    
    cJSON * root = cJSON_Parse((const char*)message);
    if (cJSON_GetErrorPtr() == 0) {
        debug_print("%s\n", "Parseable message");
        printf("got json: %s\n", cJSON_Print(root));

        cJSON *first_item = cJSON_GetArrayItem(root, 0);
        if (cJSON_GetErrorPtr() != 0) {
            debug_print("%s\n", "error: first item bad");
            return;
        }
        debug_print("First_item: %s\n", cJSON_Print(first_item));
        cJSON *second_item = cJSON_GetArrayItem(root, 1);
        if (cJSON_GetErrorPtr() != 0) {
            debug_print("%s\n", "error: second item bad");
            return;
        }
        debug_print("Second_item %s\n", cJSON_Print(second_item));

        if (0 == strcmp(cJSON_Print(first_item), "\"justsaying\"")) {
            debug_print("%s\n", "handle justsaying");
            cJSON* response = handle_justsaying(second_item);
            if (response != NULL) {
                uint8_t* responseText = (uint8_t*) cJSON_PrintUnformatted(response);
                // blocking write
                debug_print("%s\n", "Writing response");
                int wret = write_all_flush(ioc,
                            responseText,
                            strlen(responseText));
                debug_print("Respondend wret: %d\n", wret);
                if (wret != BR_ERR_OK) {
                    debug_print("%s\n", "ERROR could not respond");
                }
            }
            debug_print("%s\n", "Good. Delete response, hit the lwayer");
            cJSON_Delete(response);
        }

        if (0 == strcmp(cJSON_Print(first_item), "\"request\"")) {
            debug_print("%s\n", "handle request");
            cJSON *command_ob = cJSON_GetObjectItemCaseSensitive(second_item, "command");
            debug_print("command_ob %s\n", cJSON_Print(command_ob));
            if (cJSON_GetErrorPtr() != 0) {
                debug_print("%s\n", "a request command");
                return;
            }
            // if cmmand is subscribe send back error-tag "Im light cannot subscribe you"
        }
        cJSON_Delete(root);

        // there was no errors, check if rotation of pubkey should be done
        // let the counter be peristed instead of time-wise, TODO possible event loop this
        if (iot_dev.state == LOGGED_IN) {
            if (iot_dev.temp_pubkey_counter > 64) {
            debug_print("%s\n", "Logged in, but need to set or rotate temp_pubkey...");
            iot_dev.temp_pubkey_counter = 1;
            rotate_temp_pubkey();
            }
            if (iot_dev.state != IS_PAIRED) {
                // send pairing message to pre-defined end
                uint8_t* pairing_msg = initiate_pairing();
                int wret_p = write_all_flush(ioc, pairing_msg, strlen(pairing_msg));
                if (wret_p != BR_ERR_OK) {
                    debug_print("%s\n", "ERROR could not send pairing msg");
                }
            }
        }
        
    } else {
        debug_print("%s\n", "failed to prase message %s %d\n", message, len);
    }
}

void strip_double_quotes(unsigned char* str) {
    // strip any "quoted" strings, not expecting longer than 8196 chars
    // usually byteball addresses, signatures, hashes
    if (str[0] == '"') {
        memmove(str, str+1, strnlen((char*)str, 8196));
    }
    // replace the last char with \0 if it is "
    if (str[strnlen((char*)str, 8196)-1] == '"') {
        str[strnlen((char*)str, 8196)-1] = '\0';
    }
}

cJSON* hub_challenge(cJSON* second_item) {
    debug_print("%s\n", "hub_challenge");
    cJSON *challenge = cJSON_GetObjectItemCaseSensitive(second_item, "body");
    char* ct = cJSON_Print(challenge);

    if (strnlen(ct, 40) != 40) {
        debug_print("%s\n", "Error: bad challenge");
        return NULL;
    }
    strip_double_quotes((unsigned char*)ct);
    debug_print("hub_challenge: challenge ct: %s \n", ct);
    
    // 1. This is a hack of object_hash.js getSourceString function
    // maybe in future make a, char* getSourceString(char* cJSON_Object); implementation

    ssize_t pubkey_short_b64_len = strnlen((const char*)iot_dev.keys->b64_pubkey_short, 128);
    debug_print("pubkey short b64 len %zd\n", pubkey_short_b64_len);
    debug_print("iot_dev.keys->b64_pubkey_short %s\n", iot_dev.keys->b64_pubkey_short);

    // challenge 40, pubkey 44 len
    char to_sign_template[] = "challenge\0s\0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0pubkey\0s\0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    ssize_t to_sign_template_len = (sizeof to_sign_template / sizeof to_sign_template[0]) - 1 ;
    //ssize_t response_len = to_sign_template_len + pubkey_short_b64_len;

    // write into char array the challenge text ct, replacing above AA...
    // then append pubkeys to it same way
    memcpy(to_sign_template+12, ct, 40);
    memcpy(to_sign_template+12+40+10, iot_dev.keys->b64_pubkey_short, 44);

    printf("\n");
    uint8_t* signature = sha256_ecc_sign((unsigned char*)to_sign_template,
            to_sign_template_len,
            iot_dev.keys->privkey);

    debug_print("%s\n", "Make response to challenge obj");
    cJSON* array = cJSON_CreateArray();
    cJSON* body = cJSON_CreateObject();
    cJSON* body_obj = cJSON_CreateObject();
    debug_print("%s\n", "ready to rock");
    cJSON_AddItemToArray(array, cJSON_CreateString("justsaying"));
    cJSON_AddItemToArray(array, body);
    cJSON_AddItemToObject(body, "body", body_obj);
    cJSON_AddStringToObject(body, "subject", "hub/login");
    cJSON_AddStringToObject(body_obj, "pubkey", iot_dev.keys->b64_pubkey_short);
    cJSON_AddStringToObject(body_obj, "signature", b64_encode(signature, 64));
    cJSON_AddStringToObject(body_obj, "challenge", ct);
    debug_print("Made respond object: %s\n", cJSON_Print(array));
    return array;
}

cJSON* rotate_temp_pubkey() {
    // sha256_ecc_sign("temp_pubkey\0s\0AAAANEW_TEMP_PUBKEYAAAA\0pubkey\0\s$pub_key_short_b64\0");
    cJSON* array = cJSON_CreateArray();
    cJSON* body = cJSON_CreateObject();
    cJSON* body_obj = cJSON_CreateObject();
    cJSON* params = cJSON_CreateObject();
    cJSON* params_obj = cJSON_CreateObject();
    cJSON_AddItemToArray(array, cJSON_CreateString("request"));
    cJSON_AddItemToArray(array, body);
    cJSON_AddItemToObject(body, "body", body_obj);
    cJSON_AddStringToObject(body, "command", "hub/temp_pubkey");
    cJSON_AddItemToObject(body_obj, "params", params);
    cJSON_AddStringToObject(params, "temp_pubkey", iot_dev.temp_keys->b64_pubkey_short);
    uint8_t template[] = "temp_pubkey\0s\0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\0pubkey\0s\0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\0";
    uint16_t template_len = (sizeof(template) / sizeof(template[0])) - 1;
    memcpy(template+13, iot_dev.temp_keys->b64_pubkey_short, 44);
    memcpy(template+13+44+9, iot_dev.temp_keys->b64_pubkey_short, 44);

    uint8_t* signature = sha256_ecc_sign(template, template_len, iot_dev.keys->privkey);
    cJSON_AddStringToObject(params, "pubkey", iot_dev.keys->b64_pubkey_short);
    cJSON_AddStringToObject(params, "signature", b64_encode(signature, 64));
    cJSON_AddStringToObject(body_obj, "tag", "random_tag"); // TODO
    return array;
    // add tag to app_state->pushed_tags
    /* 
     * "request",{"command":"hub/temp_pubkey","params":{"temp_pubkey":"AxfUYhzB9TnWXBKYYlWae0p88q0Lm/0wIWhDrBxRIwWQ","pubkey":"AkroUsElGAMq4MnLWlUttOOgyHVVDZAi4EiykGak1egM","signature":"8m06FKzmBxbD15FB2PW87R9P1fRKA9fpGOR1Q6PGW1J1wzYebHnknelzkpw8ZxRhYZpWiHZKgFpGc872Xbd52w=="},"tag":"TYr1LAPAkEiPPMkZKm+QAfVSMy0O1lBn9w9uQpzWTX8="}
     *
     * when sending that, look for 
     * ["response",{"tag":"TYr1LAPAkEiPPMkZKm+QAfVSMy0O1lBn9w9uQpzWTX8=","response":"updated"}] 
     * and delete app_state->pushed_tags tag, and app_state->temp_pubkey_counter++ or 1 when > 64
     * */
}

// used as indicator of hub/login success
cJSON* hub_push_project_number(cJSON* second_item) {
    debug_print("%s\n", "hub_push_project_number");
    cJSON *body = cJSON_GetObjectItemCaseSensitive(second_item, "body");
    if (NULL != strstr(cJSON_PrintUnformatted(body), "\0 projectNumber")) {
        // ["justsaying",{"subject":"hub/push_project_number","body":{"projectNumber":0}}]
        iot_dev.state |= LOGGED_IN;
        rotate_temp_pubkey();
    }
    return NULL;
}

cJSON* info(cJSON* second_item) {
    debug_print("%s\n", "info");
    cJSON *body = cJSON_GetObjectItemCaseSensitive(second_item, "body");
    debug_print("info-body is %s\n", cJSON_Print(body));
    if (NULL != strstr(cJSON_PrintUnformatted(body), "\0 messages sent")) {
        debug_print("%s\n", "body contains str 0 messages sent");
    } else {
        // have new messages, fetch them, TODO
    }
    
    return NULL;
}

cJSON* subscribe(cJSON* second_item, char* tag) {
    cJSON* command = cJSON_GetObjectItemCaseSensitive(second_item, "command");
    if (0 == strncmp(cJSON_Print(command), "\"subscribe", 10)) {
        debug_print("%s\n", "is subcsribe");
        cJSON* in_tag = cJSON_GetObjectItemCaseSensitive(second_item, "tag");
        uint8_t template[] = "[\"response\",{\"tag\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"response\":{\"error\":\"I'm light\"}}]";
        memcpy(template+19, cJSON_PrintUnformatted(in_tag), 42);
        cJSON* response = cJSON_Parse(template);
        return response;
    }
    return NULL;
}

void handle_pairing_message() {
    // send one back in reverse if not in list of correspondents already
}

cJSON* hub_message(cJSON* second) {
    // handle a justsaying hub/message
    // body.message body.messsage_hash
    // validate is for me
    // body.signature body.pubkey to
    // body.encryptedPackage
    // body.encryptedPacakge.dh
    // body.encryptedPacakge.dh.sender_ephemeral_pubkey
    // body.encryptedMessage
    // decryptPackage(body.encryptedPackage)
    // check if is paired/known pubkey
    // send back hub/delete message_hash
}



char* createEncryptedPackage(uint8_t* json, uint8_t recipient_pubkey) {
    // stringify json
    keypair sender_ephemeral;
    uecc_make_keys(sender_ephemeral.privkey, sender_ephemeral.pubkey);
    uint8_t* shared_secret_src = uecc_shared_secret(sender_ephemeral.privkey, recipient_pubkey);
    uint8_t shared_secret[16];
    sha256_digest(shared_secret_src, shared_secret, 16);
    // get 12 random for iv
    // chunk aes_gcm_encrypt, iv)
    // gcm_get_tag
    // b64_encode(encrypted_message_buf, encrypted_message);
    // HAVE encrypted_message, iv, auth_tag, dh { sender_ephemeral.pubkey recipient_pubkey
    return "";
}

uint8_t* getDeviceAddress(uint8_t* recipient) {
    // is getChash160(getSourceString('0' + recipient_device_pubkey))
    uint8_t* rec;
    rec = malloc(33); // size of device pubkey is base58 32chars.
    uint8_t src_str = snprintf(rec, sizeof(rec), "0%s", recipient);
    return getChash160(src_str);
}

void make_pairing_message() {
    struct pairingInfo {
        char* pairing_secret;
        char* device_pubkey;
        char* my_device_address;
        char* hub;
    };
    uint8_t encryped_package;
    uint8_t* recipient_device_pubkey = "baherahace_PUBKEY/caffe"; // pick light wallet
    char* recipient_tpk = justsaying("hub/get_temp_pubkey", recipient_device_pubkey);
    uint8_t* json = "";
    char* encrypted_package = createEncryptedPackage(json, recipient_device_pubkey);
    char* enc_p_b64;
    b64_encode(encrypted_package, sizeof(encrypted_package) / sizeof(encrypted_package[0]));
    uint8_t* reciever = getDeviceAddress(recipient_device_pubkey);
    // objDeviceMessage = { encryptedPackage: ep, to: reciever, pubkey: myPubKey}; // becomes
    // "encryptedPackage\0s\0_ENCRYPTED_PACKAGE_\0to\0s\0_TO_\0pubkey\0s\0_myPubKey_\0"
    // from getDeviceMessageHashToSign(getSourceString(objDeviceMessage), permPrivKey)
    
    // when reciever decrypts encrypted_package he shall see TODO MAKE THIS, encrypt it as encrypted_message field
    // {"from":"0pubkey_capitals",
    // "device_hub":"byteroll.com/bb",
    // "subject":"pairing",
    // "body":
    //      {"pairing_secret":"poeni4bca4",
    //       "device_name":"ahhuh",
    //       "reverse_pairing_secret":"tcwOQY0znyWW"
    //       }
    // }
    // sha256_ecc_sign(getDeviceMessageHashToSign(ep), my_privkey);
    /*
     * the following is received/from-hub
    ["justsaying",
         {"subject":"hub/message",
         "body":{"message_hash":"WavN1ClULDuAGGy0JfOz6OHUTgwp7EhR6sRD3W+E7hw=",
                 "message":{"encrypted_package":
                         {"encrypted_message":"A/S/L?",

                            "iv":"uC1Zo+DKNRugkwji",
                            "authtag":"mdezSMCO4aXdMP3jwmzJFQ==",
                            "dh":{"sender_ephemeral_pubkey":"A/b",
                                  "recipient_ephemeral_pubkey":"A/U"}
                          },
                          "to":"03VOSPICO36TKJICT7ULLKVBW6AXOYURC",
                          "pubkey":"covfefefe",
                          "signature":
                "G=="}
                }
            }]
        make the following, to send/to initiate pairing
        [ "request", {"command":"hub/deliver", "params":
            {"encrypted_package":"", "iv": "", "auth_tag": "",
                "dh": {"",""}, "to": "CHASH", pubkey:"aa", signature:"", tag:""
            }]
            TODO
      */
}


cJSON* hub_message_box_status(cJSON* second_item) {
    // send back, read the tag and put in 
    //cJSON* object = cJSON_getObjectItem(second_item, 0);
    // TODO
    return NULL;
}

cJSON* light_get_history() {
    /*
     * make request like this:
     * push the tag to a map
    ["request",{"command":"light/get_history","params":{"witnesses":["7ULGTPFB72TOYA67YNGMX2Y445FSTL7O","BVVJ2K7ENPZZ3VYZFWQWK7ISPCATFIW3","DJMMI5JYA5BWQYSXDPRZJVLW3UGL3GJS","FOPUBEUPBC6YLIQDLKL6EW775BMV7YOH","GFK3RDAPQLLNCMQEVGGD2KCPZTLSG3HN","H5EZTQE7ABFH27AUDTQFMZIALANK6RBG","I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT","JPQKPRI5FMTQRJF4ZZMYZYDQVRD55OTC","OYW2XTDKSNKGSEZ27LMGNOPJSYIXHBHC","S7N5FE42F6ONPNDQLCF64E2MGFYKQR2I","TKT4UESIKTTRALRRLWS4SENSTJX6ODCW","UENJPVZ7HVHM6QGVGT6MWOJGGRTUTJXQ"],"addresses":["BH6TM5RRAH3JRLDUN74UY4NKUF4MKGKT"],"last_stable_mci":0},"tag":"9WQMKCTFsDH62AbzzXBjiSHs6dk1BQxdORUF0mTONgs="}]
    receive response like this, map tag lookup, then parse response
  ["response",{"tag":"9WQMKCTFsDH62AbzzXBjiSHs6dk1BQxdORUF0mTONgs=","response":{}}] 
     */
}

cJSON* version(cJSON* incoming) {
    // construct justsaying version message
    cJSON *array;
    cJSON *body;
    cJSON *body_obj;
    array = cJSON_CreateArray();
    body = cJSON_CreateObject();
    body_obj = cJSON_CreateObject();
    cJSON_AddItemToArray(array, cJSON_CreateString("justsaying"));
    cJSON_AddItemToArray(array, body);
    cJSON_AddItemToObject(body, "body", body_obj);
    cJSON_AddStringToObject(body, "subject", "version");
    cJSON_AddStringToObject(body_obj, "protocol_version", "1.0");
    cJSON_AddStringToObject(body_obj, "alt", "1");
    cJSON_AddStringToObject(body_obj, "program", "byteball-iot");
    cJSON_AddStringToObject(body_obj, "program_version", "2.13.8");
    cJSON_AddStringToObject(body_obj, "library", "byteballcore");
    cJSON_AddStringToObject(body_obj, "library_version", "0.2.38");
    debug_print("Made respond object: %s\n", cJSON_Print(array));
    return array;
}

