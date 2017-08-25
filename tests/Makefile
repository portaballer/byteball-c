TARGET = bb_msg_tests
CC = gcc

INCLUDES = -I../module_httpd -I../includes -I../module_bearssl \
	   -I../module_bearssl/BearSSL/inc -I../module_bearssl/BearSSL/src \
	   -I../module_bearssl/BearSSL/src/ssl -I../module_cjson -I../module_microecc \
	   -I../module_b64

CFLAGS = -g -Wall -std=gnu99 -O2 \
	 -DuECC_CURVE=uECC_secp256k1 -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 \
	 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256r1=0 -DuECC_SUPPORTS_secp256k1=1 \
	 -DuECC_SUPPORT_COMPRESSED_POINT=1 -DuECC_OPTIMIZATION_LEVEL=2 \
	 -DuECC_VLI_NATIVE_LITTLE_ENDIAN=0 -DDEBUG 

.PHONY: default all clean

all: $(TARGET)

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

modules_ := ../module_cjson/cJSON.o \
    ../module_microecc/uECC.o \
    ../module_b64/encode.o \
    ../module_b64/decode.o  \
    $(shell find ../module_bearssl/BearSSL/build/obj/*.o) 

%.o: %.c $(HEADERS) $(modules_)
	echo Making objects $<
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES)

# ../module_cjson/%.o: %.c $(HEADERS)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES)
# 
# ../module_microecc/%.o: %.c $(HEADERS)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES)
# 
# ../module_b64/%.o: encode.c decode.c $(HEADERS)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES)
# 
# ../module_bearssl/BearSSL/src/ssl/%.o: %.c $(HEADERS)
#	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDES)

bb_msg_tests: $(modules_) $(shell find ../module_bearssl/BearSSL/build/obj/*.o)
	$(CC) $(CFLAGS) $^ -Wall -o $@ bb_msg_tests.c $(INCLUDES)

$(TARGET): $(OBJECTS) $(modules_)
	echo Making target
	$(CC) $^ -Wall -o $@

clean:
	-rm -f *.o $(TARGET)

#bearssl_objects := module_bearssl/BearSSL/build/obj/aes_common.o \
#    module_bearssl/BearSSL/build/obj/enc32be.o \
#    module_bearssl/BearSSL/build/obj/dec32be.o \
#    module_bearssl/BearSSL/build/obj/dec32le.o \
#    module_bearssl/BearSSL/build/obj/enc32le.o \
#    module_bearssl/BearSSL/build/obj/i31_sub.o \
#    module_bearssl/BearSSL/build/obj/i31_add.o \
#    module_bearssl/BearSSL/build/obj/i31_bitlen.o \
#    module_bearssl/BearSSL/build/obj/i31_decmod.o \
#    module_bearssl/BearSSL/build/obj/i31_rshift.o \
#    module_bearssl/BearSSL/build/obj/i31_muladd.o \
#    module_bearssl/BearSSL/build/obj/i32_div32.o \
#    module_bearssl/BearSSL/build/obj/i31_montmul.o \
#    module_bearssl/BearSSL/build/obj/i31_tmont.o \
#    module_bearssl/BearSSL/build/obj/i31_encode.o \
#    module_bearssl/BearSSL/build/obj/i31_modpow.o \
#    module_bearssl/BearSSL/build/obj/i31_iszero.o \
#    module_bearssl/BearSSL/build/obj/i31_decode.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_i15_vrfy_asn1.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_default_sign_raw.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_i31_vrfy_asn1.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_default_vrfy_raw.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_i15_sign_asn1.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_i31_sign_asn1.o \
#    module_bearssl/BearSSL/build/obj/i31_decode.o \
#    module_bearssl/BearSSL/build/obj/i31_decode.o \
#    module_bearssl/BearSSL/build/obj/ec_secp256r1.o \
#    module_bearssl/BearSSL/build/obj/ec_secp384r1.o \
#    module_bearssl/BearSSL/build/obj/ec_secp521r1.o \
#    module_bearssl/BearSSL/build/obj/ec_c25519_m31.o \
#    module_bearssl/BearSSL/build/obj/ec_p256_m31.o \
#    module_bearssl/BearSSL/build/obj/ec_prime_i31.o \
#    module_bearssl/BearSSL/build/obj/ec_all_m31.o \
#    module_bearssl/BearSSL/build/obj/ecdsa_i31_vrfy_asn1.o \
#    module_bearssl/BearSSL/build/obj/ccopy.o \
#    module_bearssl/BearSSL/build/obj/xmem.o \
#    module_bearssl/BearSSL/build/obj/hmac.o \
#    module_bearssl/BearSSL/build/obj/hmac_ct.o \
#    module_bearssl/BearSSL/build/obj/hmac_drbg.o \
#    module_bearssl/BearSSL/build/obj/multihash.o \
#    module_bearssl/BearSSL/build/obj/ssl_hs_client.o \
#    module_bearssl/BearSSL/build/obj/ssl_client.o \
#    module_bearssl/BearSSL/build/obj/x509_minimal.o \
#    module_bearssl/BearSSL/build/obj/md5.o \
#    module_bearssl/BearSSL/build/obj/ssl_client_default_rsapub.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_ecdsa.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_rsavrfy.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_aescbc.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_aesgcm.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_descbc.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine_default_chapol.o \
#    module_bearssl/BearSSL/build/obj/ssl_client_full.o \
#    module_bearssl/BearSSL/build/obj/ssl_engine.o \
#    module_bearssl/BearSSL/build/obj/ssl_hashes.o \
#    module_bearssl/BearSSL/build/obj/ssl_io.o \
#    module_bearssl/BearSSL/build/obj/sha2small.o

