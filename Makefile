# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar


OPTEE_ROOT           ?= ..
MBEDTLS_PATH         ?= $(OPTEE_ROOT)/mbedtls
FTPM_PATH            ?= $(OPTEE_ROOT)/ms-tpm-20-ref
OPTEE_CLIENT_PATH    ?= $(OPTEE_ROOT)/optee_client
ALIAS_CERT_EXT_PATH  ?= $(OPTEE_ROOT)/alias_cert_extension
DICE_DATA_GENERATOR  ?= $(OPTEE_ROOT)/dice_data_generator

include $(ALIAS_CERT_EXT_PATH)/Makefile.am.libasncodec

CFLAGS += -I.
CFLAGS += -I$(OPTEE_CLIENT_PATH)/public
CFLAGS += -I$(FTPM_PATH)/Samples/ARM32-FirmwareTPM/optee_ta/fTPM/include
CFLAGS += -I$(FTPM_PATH)/TPMCmd/tpm/include
CFLAGS += -Imbedtls/include
CFLAGS += -I$(ALIAS_CERT_EXT_PATH)
CFLAGS += $(ASN_MODULE_CFLAGS)
CFLAGS += -Wall
CFLAGS += -g3

LD_TEEC += -L $(OPTEE_ROOT)/out-br/per-package/optee_client_ext/target/usr/lib/ -lteec

REQUIRED_HEADER_FILES = cert_root.h

# Note the order of this list matters
# See https://github.com/Mbed-TLS/mbedtls#compiling
MBEDTLS_LIBRARY_NAMES = libmbedtls.a libmbedx509.a libmbedcrypto.a
MBEDTLS_LIBRARY_PATHS = $(addprefix mbedtls/library/,$(MBEDTLS_LIBRARY_NAMES))

.PHONY: all clean

all: ra_verifier ra_attestee

# The install-* targets of the dice_data_generator shouldn't be executed in parallel
# Building ra_verifier is fast anyways, so just prohibit parallelization.
.NOTPARALLEL:

$(REQUIRED_HEADER_FILES):
	$(MAKE) -C $(DICE_DATA_GENERATOR) install-$@ INSTALL_PATH=$(abspath .)

mbedtls:
	cp -r $(MBEDTLS_PATH) .
	$(MAKE) -C mbedtls/library clean

$(MBEDTLS_LIBRARY_PATHS): | mbedtls
	$(MAKE) -C mbedtls/library CC="$(CC)" AR="$(AR)" $(@F)

ra_verifier: ra_verifier.c common.h common.c $(MBEDTLS_LIBRARY_PATHS) $(REQUIRED_HEADER_FILES)
	@echo	"Cross compile path: " $(CROSS_COMPILE)
	@echo "  CC      $@"
	$(CC) -o $@ $(CFLAGS) $(addprefix $(ALIAS_CERT_EXT_PATH)/,$(ASN_MODULE_SRCS)) $< $(MBEDTLS_LIBRARY_PATHS) common.c

ra_attestee: ra_attestee.c common.h common.c
	@echo	"Cross compile path: " $(CROSS_COMPILE)
	@echo "  CC      $@"
	$(CC) -o $@ $(CFLAGS) $(LD_TEEC) $< common.c

clean:
	rm -rf ra_verifier ra_attestee mbedtls $(REQUIRED_HEADER_FILES)
