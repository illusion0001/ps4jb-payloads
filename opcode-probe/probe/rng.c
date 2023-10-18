#include "rng.h"

#include <stdint.h>

static const uint64_t rng_a = 6364136223846793005ULL;
static const uint64_t rng_c = 1442695040888963407ULL;

static uint64_t state = 0;

void next_state() {
    state = state * rng_a + rng_c;
}

void init_rng(uint64_t seed) {
    state = seed;
    next_state();
}

uint8_t random_uint8_t() {
    next_state();
    return (state >> 32);
}

uint16_t random_uint16_t() {
    next_state();
    return (state >> 32);
}

uint32_t random_uint32_t() {
    next_state();
    return (state >> 32);
}
