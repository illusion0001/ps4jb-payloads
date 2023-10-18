#include "hash.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void hash_combine(size_t* seed, size_t value) {
    *seed = value + 0x9e3779b9 + (*seed << 6) + (*seed >> 2);
}

size_t memhash(void* addr, size_t size) {
    size_t seed = 0;
    for (size_t i = 0; i < size; ++i) {
        hash_combine(&seed, ((uint8_t*)addr)[i]);
    }
    return seed;
}

int comp_hshtbl(const void *lhs_, const void *rhs_) {
    const struct hshtbl_node* lhs = lhs_;
    const struct hshtbl_node* rhs = rhs_;
    if (lhs->hash > rhs->hash) {
        return 1;
    }
    if (lhs->hash < rhs->hash) {
        return -1;
    }
    return 0;
}

void sort_hshtbl(struct hshtbl_node* hshtbl, size_t size) {
    qsort(hshtbl, size, sizeof(struct hshtbl_node), comp_hshtbl);
}

struct hshtbl_node* find_hshtbl(struct hshtbl_node* hshtbl, size_t size, size_t hash) {
    struct hshtbl_node target = {
        .hash = hash,
        .value = 0
    };
    struct hshtbl_node* result = bsearch(&target, hshtbl, size, sizeof(struct hshtbl_node), comp_hshtbl);
    while (result != NULL && result > hshtbl && comp_hshtbl(result - 1, &target) == 0) {
        --result;
    }
    return result;
}
