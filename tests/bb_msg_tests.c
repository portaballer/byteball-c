#include <stdio.h>

#include "cJSON.h"
#include "byteball_msgs.h"
#include "byteball_device.h"

char* js_version = "[\"justsaying\",{\"subject\":\"version\",\"body\":{\"protocol_version\":\"1.0\",\"alt\":\"1\",\"library\":\"byteballcore\",\"library_version\":\"0.2.41\",\"program\":\"headless-byteball\",\"program_version\":\"0.1.7\"}}]";
char* js_hub_challenge = "[\"justsaying\",{\"subject\":\"hub/challenge\",\"body\":\"kl8uYkq0FG/elGPGTTCGIfeMzAoPTP5z5C7Kc5a7\"}]";
char* js_login = "[\"justsaying\",{\"subject\":\"hub/login\",\"body\":{\"challenge\":\"G4uHsvfxKxPS/EOMDSbsfkLoEx3Uan18fnIgshvo\",\"pubkey\":\"Ass7pBOZx4HHbbtT5J6820maRoFQzmVynWFgxyF6As+a\",\"signature\":\"jiBINsdAgo8eQT/mYZA5CNRqQ5giPGGofwSBVFH0FEZ/a6n72CzLBTqT1huOk/TCm2OX0xwm1NKubg/TaRr1MA==\"}}]";
char* js_info = "[\"justsaying\",{\"subject\":\"info\",\"body\":\"0 messages sent\"}]";
char* js_hub_message_box_status = "[\"justsaying\",{\"subject\":\"hub/message_box_status\",\"body\":\"empty\"}]";

char* js_pairing;

char* req_subscribe = "[\"request\",{\"command\":\"subscribe\",\"params\":{\"subscription_id\":\"qbmBX1S8icmZNLjnkPeFm5VEgjf0/IjkgPcbpIjE\",\"last_mci\":697129},\"tag\":\"cqAdJXmmZK2WDTu4speqT3seWllYXrjkTBJVqbQ3xuA=\"}]";
char* req_hub_temppubkey = "[\"request\",{\"command\":\"hub/temp_pubkey\",\"params\":{\"temp_pubkey\":\"HASH\", \"pubkey\":\"MAHPUBKEY\",\"signature\":\"SIG_HASH\"},\"tag\":\"TAG_HASH\"}]";
char* req_hub_get_temppubkey = "[\"request\",{\"command\":\"hub/get_temp_pubkey\",\"params\":\"AvXedtYcBlUypM1DXDowyM8dGsJV4wX6wMlMjCdR9N6A\",\"tag\":\"e8NYdRGeG9CidvmVJ/5eweWIKAcu1jptRIQFMpRsxis=\"}]";

char* resp_subscribe = "[\"response\",{\"tag\":\"HASH\",\"response\":{\"Im light\"}}]";

keypair keys;
keypair temp_keys;
bb_device iot_dev;
int main(int argc, char* argv[]) {
    debug_print("%s\n", "Unit testing");
    cJSON* answer = NULL;

    // unit tester
    iot_dev.keys = &keys;
    iot_dev.temp_keys = &temp_keys;
    init_bb_device(&iot_dev);

    debug_print("%s\n", iot_dev.keys->b64_pubkey_short);

    // tests
    answer = version(js_version);
    debug_print("version Answer %s\n", cJSON_Print(answer));
    cJSON* type = cJSON_GetArrayItem(answer, 0);
    cJSON* object = cJSON_GetArrayItem(answer, 1);
    debug_print("type %s\n", cJSON_Print(type));
    cJSON* body = cJSON_GetObjectItemCaseSensitive(object, "body");
    debug_print("body %s\n", cJSON_Print(body));
    cJSON_Delete(answer);

    answer = rotate_temp_pubkey();
    debug_print("rotate Answer %s\n", cJSON_Print(answer));
    cJSON_Delete(answer);

    debug_print("%s\n", "Respond to hub/challenge with hub/login");
    cJSON* hc = cJSON_Parse(js_hub_challenge);
    debug_print("%s\n", cJSON_Print(hc));
    answer = hub_challenge(cJSON_GetArrayItem(hc, 1));
    // answer == justsaying->hub_login
    debug_print("hub/challenge Answer: %s\n", cJSON_Print(answer));
    cJSON_Delete(answer);

    cJSON* sub = cJSON_Parse(req_subscribe);
    answer = subscribe(cJSON_GetArrayItem(sub, 1), "taggahgekjreara");
    debug_print("subscribe Answer: %s\n", cJSON_Print(answer));
    // response->subscribe == answer // In light.
    cJSON_Delete(answer);

    cJSON* inf = cJSON_Parse(js_info);
    answer = info(cJSON_GetArrayItem(inf, 1));
    debug_print("info Answer: %s\n", cJSON_Print(answer));
    // answer == response->hub_temp_pubkey; // hub_temp_pubkey ?
    cJSON_Delete(answer);

    // OK, test for sending/receiving messages
    answer = hub_message_box_status(js_hub_message_box_status);
    // if 0 do nothing, else expect hub/refresh or something
    // // other test case hub_message_box_status 4 messages.
    // // expect a hub/refresh
    debug_print("hub_message_box_status Answer: %s\n", cJSON_Print(answer));
    cJSON_Delete(answer);
    
    //answer = deliver(js_example_message);
    // extract/get pubkey from hub response
    //cJSON_Delete(answer);

    // deriveSharedSecret
    // encryptPackage
    // decryptPackage, aes-128-gcm
    
    answer = pair(js_pairing);
    debug_print("pair Answer: %s\n", cJSON_Print(answer));
    cJSON_Delete(answer);

    // run refresh on startup or X days
    //answer = refresh(js_hub_refresh);
    // incoming message sent to us or log in first
    //cJSON_Delete(answer);

    //answer = message(js_hub_message);
    // incoming message sent to us
    //cJSON_Delete(answer);

    //answer = message_delete(js_hub_delete);
    // should recieve a hub/delete from bb-iot with message-hash to delete from hub.
    //cJSON_Delete(answer);

    // unit test: send 4 messages from hub to device, require a hub/delete for each.
    return 0;
}
