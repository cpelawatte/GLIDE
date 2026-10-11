/* host-test stand-in CSPRNG: "seeded" only when GLIDE_SEEDED=1 (tests the
 * fail-closed path); deterministic stream so runs are reproducible. */
#include "lib/csprng.h"
#include <stdlib.h>
static uint64_t st = 99;
bool csprng_rand(uint8_t *r, size_t n)
{
    const char *s = getenv("GLIDE_SEEDED");
    if(!s || *s != '1') {
        return false;
    }
    for(size_t i = 0; i < n; i++) {
        st = st * 2862933555777941757ULL + 3037000493ULL;
        r[i] = (uint8_t)(st >> 56);
    }
    return true;
}
