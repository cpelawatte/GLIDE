/* host-test stand-in for Contiki-NG os/lib/csprng.h: same macros and API */
#ifndef CSPRNG_H_
#define CSPRNG_H_
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef CSPRNG_CONF_ENABLED
#define CSPRNG_ENABLED CSPRNG_CONF_ENABLED
#else
#define CSPRNG_ENABLED 0
#endif
bool csprng_rand(uint8_t *result, size_t len);
#endif
