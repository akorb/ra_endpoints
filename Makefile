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
ASN1C_GEN_PATH       ?= $(OPTEE_ROOT)/asn1c_generations
CERTS_WORKSPACE_PATH ?= $(OPTEE_ROOT)/certs_workspace

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

REQUIRED_HEADER_FILES = TCIs.h cert_root.h

# Note the order of this list matters
# See https://github.com/Mbed-TLS/mbedtls#compiling
MBEDTLS_LIBRARY_NAMES = libmbedtls.a libmbedx509.a libmbedcrypto.a
MBEDTLS_LIBRARY_PATHS = $(addprefix mbedtls/library/,$(MBEDTLS_LIBRARY_NAMES))

.PHONY: all clean

all: ra_verifier

$(REQUIRED_HEADER_FILES):
	$(MAKE) -C $(CERTS_WORKSPACE_PATH) install-$@ INSTALL_PATH=$(abspath .)

mbedtls:
	cp -r $(MBEDTLS_PATH) .
	$(MAKE) -C mbedtls/library clean

$(MBEDTLS_LIBRARY_PATHS): | mbedtls
	$(MAKE) -C mbedtls/library CC="$(CC)" AR="$(AR)" $(@F)

ra_verifier: ra_verifier.c $(MBEDTLS_LIBRARY_PATHS) $(REQUIRED_HEADER_FILES)
	@echo	"Cross compile path: " $(CROSS_COMPILE)
	@echo "  CC      $@"
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(addprefix $(ASN1C_GEN_PATH)/,$(ASN_MODULE_SRCS)) $< $(MBEDTLS_LIBRARY_PATHS)

clean:
	rm -rf ra_verifier mbedtls $(REQUIRED_HEADER_FILES)
