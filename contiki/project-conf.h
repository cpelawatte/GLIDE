/*
 * project-conf.h -- build configuration for the GLIDE device firmware.
 * Picked up automatically by Contiki-NG's Makefile.include for every target
 * built from contiki/; target-specific settings are guarded below.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifdef CONTIKI_TARGET_CC2538DK
/* Cryptographic random source for e_d and nonce_d: Contiki-NG's AES-based
 * CSPRNG (os/lib/csprng.c), seeded at boot from radio I/Q noise by
 * cc2538-rf.c (iq_seeder_seed). If seeding fails the radio driver asserts,
 * and csprng_rand() returns false while unseeded, so the device fails closed.
 * Deliberately NOT LPM_CONF_MAX_PM 2: that would add the SRAM seeder but
 * restrict all RAM to the 16 KB retention half (cc2538.lds). */
#define CSPRNG_CONF_ENABLED 1
#endif /* CONTIKI_TARGET_CC2538DK */

#endif /* PROJECT_CONF_H_ */
