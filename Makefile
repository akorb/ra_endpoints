# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

OUT_DIR ?= .

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc


OPTEE_ROOT        ?= ..
MBEDTLS_PATH      ?= $(OPTEE_ROOT)/mbedtls
FTPM_PATH         ?= $(OPTEE_ROOT)/ms-tpm-20-ref
OPTEE_CLIENT_PATH ?= $(OPTEE_ROOT)/optee_client
ASN1C_GEN_PATH    ?= $(OPTEE_ROOT)/asn1c_generations

include $(ASN1C_GEN_PATH)/Makefile.am.libasncodec

CFLAGS += -I.
CFLAGS += -I$(OPTEE_CLIENT_PATH)/public
CFLAGS += -I$(FTPM_PATH)/Samples/ARM32-FirmwareTPM/optee_ta/fTPM/include
CFLAGS += -I$(FTPM_PATH)/TPMCmd/tpm/include
CFLAGS += -Imbedtls/include
CFLAGS += -I$(ASN1C_GEN_PATH)
CFLAGS += $(ASN_MODULE_CFLAGS)
CFLAGS += -Wall
CFLAGS += -g3

LDFLAGS += -L $(OPTEE_ROOT)/out-br/per-package/optee_client_ext/target/usr/lib/ -lteec

.PHONY: all clean

all: ra_verifier

mbedtls:
	$(MAKE) -C $(MBEDTLS_PATH) clean
	$(MAKE) -C $(MBEDTLS_PATH) CC="$(CC)" install DESTDIR=$(shell pwd)/mbedtls
	$(MAKE) -C $(MBEDTLS_PATH) clean

$(OUT_DIR)/ra_verifier: ra_verifier.c mbedtls
	@echo	"Cross compile path: " $(CROSS_COMPILE)
	@echo "  CC      $@"
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) -Wno-suggest-attribute=format $(addprefix $(ASN1C_GEN_PATH)/,$(ASN_MODULE_SRCS)) $< mbedtls/lib/libmbedtls.a mbedtls/lib/libmbedx509.a mbedtls/lib/libmbedcrypto.a

clean:
	rm -rf ra_verifier mbedtls
