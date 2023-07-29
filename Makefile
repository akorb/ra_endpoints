# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

out-dir := .

CC		= $(CROSS_COMPILE)gcc
CPP		= $(CROSS_COMPILE)cpp
LD		= $(CROSS_COMPILE)ld
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump
READELF		= $(CROSS_COMPILE)readelf

OPTEE_ROOT ?= ..

# Macros to detect the targeted architecture (e.g., arm-linux-gnueabihf or
# aarch64-linux-gnu) and the corresponding bit size (32 or 64).
define cc-arch
$(shell $(1) -v 2>&1 | grep Target | sed 's/Target: \([^-]*\).*/\1/')
endef
define cc-bits
$(if $(filter arm, $(1)),32,$(if $(filter aarch64, $(1)),64,unknown-arch))
endef

srcs := ra_verifier.c

objs 	:= $(patsubst %.c,$(out-dir)/%.o, $(srcs))

CFLAGS += -I./

CFLAGS += -I$(OPTEE_ROOT)/optee_client/public

CFLAGS += -Wall -Wcast-align -Werror \
	  -Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	  -Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
	  -Wmissing-declarations -Wmissing-format-attribute \
	  -Wmissing-include-dirs \
	  -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
	  -Wshadow -Wstrict-prototypes -Wswitch-default \
	  -Wwrite-strings -Wno-unused-parameter \
	  -Wno-declaration-after-statement \
	  -Wno-missing-field-initializers -Wno-format-zero-length

CFLAGS += -g3

LDFLAGS += -L $(OPTEE_ROOT)/out-br/target/usr/lib/ -lteec

.PHONY: all
all: ra_verifier

ra_verifier: $(objs)
	@echo	"Cross compile " $(CROSS_COMPILE)
	@echo "  LD      $(out-dir)/$@"
	$(CROSS_COMPILE)$(CC) -o $(out-dir)/$@ $+ $(LDFLAGS)

$(out-dir)/%.o: $(CURDIR)/%.c
	@echo "Cross compile=" $(CROSS_COMPILE)
	@echo "CC=" $(CC)
	@echo '  CC      $<'
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $< -o $@

RMDIR := rmdir --ignore-fail-on-non-empty
define rm-build-dirs
	$(q)for d in $1; do $(RMDIR) $(out-dir)/ra_verifier/$$d 2> /dev/null; true; done
	$(q)$(RMDIR) $(out-dir)/ra_verifier 2> /dev/null; true
	$(q)$(RMDIR) $(out-dir) 2> /dev/null; true
endef

install:
	$(echo) '  INSTALL ${DESTDIR}${bindir}'
	$(q)mkdir -p ${DESTDIR}${bindir}
	$(q)cp $(out-dir)/ra_verifier/ra_verifier ${DESTDIR}${bindir}

.PHONY: clean
clean:
	@echo '  CLEAN $(out-dir)'
	$(q)rm -f $(out-dir)/ra_verifier/ra_verifier
	$(q)$(foreach obj,$(objs), rm -f $(obj))
	$(q)rm -f $(cleanfiles)
	$(call rm-build-dirs)
