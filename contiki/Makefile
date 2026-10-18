CONTIKI_PROJECT = device_auth_main
all: $(CONTIKI_PROJECT)

# device_auth_main.c builds for cooja (Cooja native mote), cc2538dk
# (footprint, scripts/cap_evidence.sh) and native (host e2e test).
TARGET ?= cooja

PROJECT_SOURCEFILES += device_auth.c
PROJECT_SOURCEFILES += beacon_client.c
PROJECT_SOURCEFILES += hkdf_sha256.c
PROJECT_SOURCEFILES += sha256_impl.c

MODULES += os/net/security/micro-ecc
CFLAGS += -DuECC_SUPPORTS_secp256r1=1
CFLAGS += -DuECC_SUPPORT_COMPRESSED_POINT=1
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=2

CFLAGS += -Os
# Cooja native motes: Ubuntu's GCC enables _FORTIFY_SOURCE by default, which
# turns printf() into __printf_chk(). Cooja only redirects printf/puts/putchar
# into the mote log (-Wl,--wrap), so formatted output would bypass Mote output
# and the Serial Socket. Host hardening has no meaning for a simulated mote.
ifeq ($(TARGET),cooja)
CFLAGS += -U_FORTIFY_SOURCE
endif
CFLAGS += -Wno-error=format -Wno-error=format-extra-args

CONTIKI_NG_PATH ?= /home/csp/Desktop/contiki-ng
MAKE_ROUTING = MAKE_ROUTING_NULLROUTING
MAKE_NET = MAKE_NET_IPV6
include $(CONTIKI_NG_PATH)/Makefile.include
