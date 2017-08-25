
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// lwip later on esp, socket based
//#include "lwip/netdb.h"
//#include "lwip/err.h"
//#include "lwip/sys.h"
//#include "lwip/dns.h"
//#include "lwip/api.h"
//#include "lwip/sockets.h"

// switch to above, from lwip, later
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#include <cJSON.h>
#include "b64.h"
#include "bearssl.h"

#include "byteball_wss.h"

//#include "espressif/esp_common.h"
//#include "esp/uart.h"
//#include "esp/hwrand.h"

//#include "FreeRTOS.h"
//#include "task.h"

//#include "ssid_config.h"

// Low-level data read callback for the simplified SSL I/O wrapper API.
static int sock_read(void *ctx, unsigned char *buf, size_t len_in) {
    for (;;) {
        ssize_t rlen;

        // ctx here is context pointer, to fd of connect()
        rlen = read(*(int *)ctx, buf, len_in);
        if (rlen <= 0) {
            if (rlen < 0 && errno == EINTR) {
                    continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

// Low-level data write callback for the simplified SSL I/O wrapper API.
// buf is already encrypted.
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    for (;;) {
        ssize_t wlen;
        wlen = write(*(int *)ctx, buf, len);
        if (wlen <= 0) {
            if (wlen < 0 && errno == EINTR) {
                    continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}

wsOnOpen wsOnOpenFunc = NULL;
wsOnMessage wsOnMessageFunc = defaultOnMessage;
uint8_t parse_frame(br_sslio_context* ioc, uint8_t* data, uint16_t frame_len) {
    debug_print("%s\n", "parse_frame");

    if (data != NULL && frame_len > 1) {

    uint8_t* message = NULL;
    uint16_t message_size = 0;

    uint8_t opcode = data[0] & 0x0F;
    uint8_t fin = data[0] & 0x80;
    uint8_t is_masked = data[1] & 0x80;
    switch (opcode) {
        case 0x00: // CONTINUATION
        case 0x01: // TEXT
        case 0x02: // BIN
            debug_print("====== Opcode: 0x%hX, frame length: %d fin: %d is_masked:%d\n",
                    opcode, frame_len, fin, is_masked);

            if (frame_len > 6) {
                int data_offset = 6;
                uint8_t *dptr = &data[6];
                uint8_t *kptr = &data[2];
                uint16_t payload_len = data[1] & 0x7F;
    
                debug_print("payload_len indicator %d\n", payload_len);
                if (payload_len == 127) {
                  /* most likely won't happen inside non-fragmented frame */
                  debug_print("%s\n", "ERROR: frame is too long ffs");
                  return FALSE;
                } else if (payload_len == 126) {
                  /* extended length */
                  dptr += 2;
                  kptr += 2;
                  data_offset += 2;
                  payload_len = (data[2] << 8) | data[3];
                } else if(payload_len < 126) {
                    data_offset = 2;
                }

                if (is_masked == 0 && payload_len > 126) {
                    data_offset = 4;
                }
    
                debug_print("Found payload_len %d\n", payload_len);
                //frame_len -= data_offset;
                uint16_t data_len = frame_len - data_offset;
                debug_print("Calculated data_len %d from frame_len %d and offset %d\n", data_len, frame_len, data_offset);
    
                if (payload_len > data_len) {
                  debug_print("Error: payload_len is bigger than data_len %d\n", payload_len);
                  return FALSE;
                }
                
                const uint16_t segmented_len = data_len - payload_len;

                // if should unmask
                if (is_masked == 1) {
                    for (int i = 0; i < data_len; i++) {
                      *(dptr++) ^= kptr[i % 4];
                    }
                }

               // debug_print("Would have message: %s\n", &data[data_offset]);

                if (opcode == 0x01 && fin == 0) {
                    debug_print("%s", "First fragment received, stashing...");
                    // stash the frame on the heap
                    if (message_size != 0) {
                        debug_print("%s\n", "... not stash. WARNING schenanigans");
                        break;
                    }
                    message = malloc(data_len + 1);
                    if (message == NULL) {
                        debug_print("%s\n", "ERROR Allocating");
                        return FALSE;
                    }
                    memset(message, 0, data_len);
                    memcpy(message, &data[data_offset], data_len);
                    message[data_len + 1] = '\0';
                    message_size += data_len;
                    debug_print("%s\n", "...stashed it");
                    break;
                }

                // 0 is clear
                if (opcode == 0x00 && fin == 0) {
                    // continuation, continue stashing on the heap or concat
                    uint8_t* temp;
                    // if (message == NULL && message_size == 0) {
                    //     debug_print("%s\n", "ERROR WARNING schenanigans");
                    //     break;
                    // }
                    if (data_len + message_size > 196608 ) { // message max
                        debug_print("%s\n", "Message would be too big, sorry");
                        break;
                    }
                    temp = realloc(message, data_len + 1);
                    if (temp == NULL) {
                        debug_print("%s\n", "ERROR allocating for continuation");
                        return FALSE;
                    }
                    memcpy(temp, &data[data_offset], data_len);
                    temp[data_len + 1] = '\0';
                    message = temp;
                    message_size += data_len;

                    if (fin) { // fin is set means is termination frame
                        debug_print("%s\n", "Termination frame");
                        if (wsOnMessageFunc != NULL) {
                            wsOnMessageFunc(ioc, message, message_size);
                        }
                        message_size = 0;
                        if (message != NULL) {
                            free(message);
                        }
                    }
                }
    
                /* user callback */
                if (opcode != 0x00 && fin != 0 && wsOnMessageFunc != NULL) {
                    debug_print("%s\n", "Calling wsOnMessage");
                    wsOnMessageFunc(ioc, &data[data_offset], payload_len);
                    if (segmented_len > 0) {
                        wsOnMessageFunc(ioc, &data[data_offset+payload_len+2], segmented_len);
                    }
                } else {
                    debug_print("%s\n", "Not calling wsOnMessageFunc");
                }
            }
            break;
        case 0x08: // close
            debug_print("%s\n", "Close requested");
            return 2;
        case 0x09:
            debug_print("%s\n", "Ping");
            break;
        case 0x10:
            debug_print("%s\n", "Pong");
            break;
        default:
            debug_print("Unsupported opcode 0x%hX", opcode);
            break;
        }
    }
    return 0;
}

static unsigned char bearssl_buffer[BR_SSL_BUFSIZE_BIDI];
static br_ssl_client_context sc;
static br_x509_minimal_context xc;
static br_sslio_context ioc;

static uint8_t is_websocket = FALSE;
static const char host[] = "byteroll.com"; // 253 chars max for domain name
const unsigned char sec_websocket_key[16];

int write_all_flush(br_sslio_context* ioc, const unsigned char* buf, size_t len) {
    for (;;) {
        debug_print("Asked to write len %zd\n", len);

        if (is_websocket) {
            debug_print("websocket write len %zd\n", len);
            uint8_t *wsbuf = malloc(len + 4);//mem_malloc(len + 4);
            if (wsbuf == NULL) {
              debug_print("%s", "err sock_write ws out of memory\n"); // ERR_MEM
              return -1;
            }

            unsigned char mask[4];
            unsigned int mask_int = rand();
            memcpy(mask, &mask_int, 4);

            int offset = 6;
            wsbuf[0] = 0x81; // TEXT_MODE with fin
            // crude, dont support fragmentation of frames or longer than 16bit, meh
            if (len > 125) {
                wsbuf[1] = 126 | 0x80; // | 0x80 sets mask bit, following 2 bytes say the len
                wsbuf[2] = len >> 8;
                wsbuf[3] = len;
                offset += 2;
            } else {
                wsbuf[1] = len;
            }

            // write the mask chars somewhere, if indicator 126 4, smaller packets start from 2
            for (int i = 0; i < 4; i++) {
                wsbuf[(offset-4)+i] = mask[i];
            }

            memcpy(&wsbuf[offset], buf, len);

            // apply the mask
            int m;
            for (m = 0; m < len; m++) {
                wsbuf[offset + m] = wsbuf[(offset + m)] ^ mask[m % 4]; //0xff;
            }
            len += offset;
 
            debug_print("writer ws sending packets \n[ %s \n].%zd \n", wsbuf, len);
            int retval = 0;
            retval = br_sslio_write_all(ioc, wsbuf, len);
            if (retval != BR_ERR_OK) {
                printf("write_all_flush failed: %d\r\n", br_ssl_engine_last_error(&sc.eng));
            }
            br_sslio_flush(ioc);
            free(wsbuf);
            return retval;

        } else {
            int retval = br_sslio_write_all(ioc, buf, len);
            if (retval != BR_ERR_OK) {
                printf("write_all_flush failed: %d\r\n", br_ssl_engine_last_error(&sc.eng));
            }
            br_sslio_flush(ioc);
            return retval;
        }
    }
}


void init_ssl(int* fd) {
    printf("Initializing BearSSL... ");
    br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);

    /*
     * Set the I/O buffer to the provided array. We allocated a
     * buffer large enough for full-duplex behaviour with all
     * allowed sizes of SSL records, hence we set the last argument
     * to 1 (which means "split the buffer into separate input and
     * output areas").
     * Last arg non-zero means full duplex.
     */
    br_ssl_engine_set_buffer(&sc.eng, bearssl_buffer, sizeof bearssl_buffer, 1);

    /*
     * Inject some entropy from the ESP hardware RNG
     * This is necessary because we don't support any of the BearSSL methods
     */
    for (int i = 0; i < 10; i++) {
        //int rand = hwrand();
        int rand = 42;
        br_ssl_engine_inject_entropy(&sc.eng, &rand, 4);
    }

    /*
     * Reset the client context, for a new handshake. We provide the
     * target host name: it will be used for the SNI extension. The
     * last parameter is 0: we are not trying to resume a session.
     */
    br_ssl_client_reset(&sc, host, 0);

    /*
     * Initialise the simplified I/O wrapper context, to use our
     * SSL client context, and the two callbacks for socket I/O.
     */
    br_sslio_init(&ioc, &sc.eng, sock_read, fd, sock_write, fd);
    printf("init ssl done.\r\n");
}


uint8_t make_str(unsigned char* init_handshake) {
    char url[] = "/bb"; // de factor 2000 chars limit, enough with 128 
    char upgrade[] = "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "; // 61
    // get 16 bytes from random, fuck it
    unsigned char few_random[16] = "lk4naca43a}a";
    few_random[15] = '\0';
    debug_print("%s\n", few_random);
    snprintf((char *)sec_websocket_key, 15, "%s", b64_encode(few_random, 16));
    if (snprintf((char*)init_handshake, 468+1,
                "GET %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\n%s%s\r\n\r\n",
                url, host, host, upgrade, sec_websocket_key) == -1) {
        printf("ERROR asprintf failed");
        return FALSE;
    }
    debug_print("Made handshake \n[\n %s \n]\n", init_handshake);
    return TRUE;
}

int run_wss(wsOnMessage messageFunc) {
    debug_print("%s\n","...");
    if (messageFunc != NULL) {
        wsOnMessageFunc = messageFunc;
        debug_print("%s\n","Uh huh ok");
    } else {
        debug_print("%s\n","Wat?");
        exit(1);
    }

    int fd = -1;
    struct addrinfo *res = NULL;

    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    int dns_err = 0;
    do {
        if (res) {
            freeaddrinfo(res);
        }
        debug_print("%s\n","sleeping 100...");
        //sleep(100); // vTaskDelay
        dns_err = getaddrinfo(host, "443", &hints, &res);
    } while(dns_err != 0 || res == NULL);

    debug_print("%s\n", "do socket");
    fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        printf("socket failed\n");
        return 1;
    }

    debug_print("init ssl fd is %d\n", fd);
    init_ssl(&fd);

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        printf("connect failed\n");
        return 1;
    }
    debug_print("%s\n","Connected");

    unsigned char req_handshake[468]; //253+128+61+26
    memset(req_handshake, 0, 468);
    make_str(req_handshake);

    // only now is the made client ssl hello sent out, with the flush
    if (write_all_flush(&ioc, req_handshake, strlen((char*)req_handshake)) != BR_ERR_OK) {
        close(fd);
        freeaddrinfo(res);
        printf("write_all_flush failed: %d\r\n", br_ssl_engine_last_error(&sc.eng));
        return 2;
    }

    // Read and print the server response
    unsigned char buf_all[192];
    memset(buf_all, 0, 192);
    int totals = 0;
    debug_print("is_websocket %d\n", is_websocket);
    while (totals < 191) {
        debug_print("...non-websocket reading...%d\n", totals);
        // 33 chars of HTTP/1.1 101 Switching Protocols
        unsigned char buf[64];
        memset(buf, 0, 64);
        int rlen;

        rlen = br_sslio_read(&ioc, buf, sizeof(buf) - 1);

        if (rlen < 0) {
            break; // error happened
        }

        if (strstr((char*)buf, "\r\n\r\n") != NULL) {
            debug_print("%s\n", "Found end of header");
            break;
        }

        if (rlen > 0 && (rlen + totals < 191)) {
            printf("RECVD %s\n", buf);
            strncpy((char*)&buf_all[totals], (char*)buf, rlen);
            totals += rlen;

            if (totals >= 33 && !is_websocket) {
                debug_print("buf all is \n[ %s \n] \n", buf_all);
                if (strncmp("HTTP/1.1 101 Switching Protocols", (const char*)buf_all, 32) == 0) {
                    printf("Switched...\n");
                    is_websocket = TRUE;
                    continue; // read more
                } else {
                    printf("wrong header closing \n");
                    break; // not 101 status code
                }
            }
            continue; // means read more
        }
    }

    // If reading the response failed for any reason, we detect it here
    if (br_ssl_engine_last_error(&sc.eng) != BR_ERR_OK) {
        close(fd);
        freeaddrinfo(res);
        printf("failure, error = %d\r\n", br_ssl_engine_last_error(&sc.eng));
        return 2;
    }

    if (is_websocket) {
        onOpen(&ioc);

        int retval;
        struct pollfd rfds[1];
        rfds[0].fd = fd;
        rfds[0].events = POLLIN;

        // event loop, this would have been easier, lighter with lwip rawapi, but oh well.
        // and go to sleep more, todo tls session resumption
        debug_print("%s\n", "Going into event loop");
        for (;;) {
            retval = poll(rfds, 1, 3500);
            if (retval == -1) {
                printf("error in poll\n");
            } else if(retval == 0) {
                printf("no data within timeval\n");
                sleep(1);
                break;
            } else {
                debug_print("%s\n","NEW DATA Available");
                if (rfds[0].events & POLLIN) {
                    int retlen;
                    uint8_t ws_data[1024]; // todo calc average Byteball json message size
                    memset(ws_data, 0, 1024);
                    debug_print("%s\n", "Requesting The Data");
                    retlen = br_sslio_read(&ioc, ws_data, sizeof(ws_data) - 1);
                    debug_print("Read possible frame %s\n", ws_data);
                    debug_print("with length %d\n", retlen);
                    if (retlen == -1) {
                        debug_print("%s\n", "ERROR READING, connection closed?");
                        sleep(1);
                        break;
                    }
                    if (retlen > 0 && is_websocket) {
                        parse_frame(&ioc, ws_data, retlen);
                    }
                }
            }
        }
    }    

    // let the websocket handlers close, but if its still http we failed so close.
    if (!is_websocket) {
        printf("Closing\n");
        if (fd != -1) {
            close(fd);
        }
        if (res != NULL) {
            freeaddrinfo(res);
        }
        return 0;
    } else {
        websocket_send_close(&ioc);
    }
    return 0;
}

uint8_t handshake_check(const unsigned char* buf_all) {
    // dont search for Sec-WebSocket-Accept header and its expected value
    // just adds more complexity for nothing
    is_websocket = TRUE;
    return TRUE;
}

void onOpen(br_sslio_context* ioc) {
    if (wsOnOpenFunc != NULL) {
        wsOnOpenFunc(ioc);
    }
    //const char* version = "[\"justsaying\",{\"subject\":\"version\",\"body\":{\"protocol_version\":\"1.0\",\"alt\":\"1\",\"library\":\"byteballcore\",\"library_version\":\"0.2.38\",\"program\":\"byteball-iot\",\"program_version\":\"1.0.1\"}}]";
    //uint16_t len = strlen((const char*)version);
    //debug_print("Sending version...\n§ %s §.%d\n", (const char*)version, len);
    //if (write_all_flush(&ioc, (unsigned char*)version, len) != BR_ERR_OK) {
    //    debug_print("%s\n", "ERROR writing");
    //    printf("br_sslio_write_all failed: %d\r\n", br_ssl_engine_last_error(&sc.eng));
    //}
    //debug_print("%s\n", "...sent version");
}

static uint8_t websocket_send_close(br_sslio_context* ioc) {
    const uint8_t buf[] = {0x88, 0x02, 0x03, 0xe8};
    uint16_t len = sizeof (buf);
    debug_print("%s\n", "wsocket closing connection");
    return write_all_flush(ioc, buf, len);
}

void defaultOnMessage(br_sslio_context* ioc, uint8_t* message, uint16_t len) {
    debug_print("RECEIVED %s\n", message);
}

