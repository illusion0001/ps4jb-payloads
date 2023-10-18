#pragma once

#include <stddef.h>
#include <stdint.h>

void hash_combine(size_t* seed, size_t value);
size_t memhash(void* addr, size_t size);

struct hshtbl_node {
    size_t hash;
    size_t value;
};

void sort_hshtbl(struct hshtbl_node* hshtbl, size_t size);
struct hshtbl_node* find_hshtbl(struct hshtbl_node* hshtbl, size_t size, size_t hash);
