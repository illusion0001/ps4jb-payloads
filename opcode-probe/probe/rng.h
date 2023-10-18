#pragma once

#include <stdint.h>

void init_rng(uint64_t seed);
uint8_t random_uint8_t();
uint16_t random_uint16_t();
uint32_t random_uint32_t();
