#include <stdlib.h>
#include <stdio.h> 
#include <stdint.h>
#include <string.h>

#include "CycleTimer.h"

void print_block_hex(uint8_t *block);
void print_block(uint8_t *block);
void add_round_key(uint8_t *block, uint8_t *key);

void mix_columns(uint8_t *block);
void sub_bytes(uint8_t *block);
void inv_sub_bytes(uint8_t *block);
void shift_rows(uint8_t *block);
void inv_shift_rows(uint8_t *block);

void expand_key(uint8_t *key, uint8_t *rkey);
void encrypt(uint8_t *block, uint8_t *key);
void aes_ctr(const uint8_t *data, uint32_t size, uint8_t *key, uint8_t *seed, uint8_t *ctext);





