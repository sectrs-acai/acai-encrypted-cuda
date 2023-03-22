#pragma once

void encrypt_cuda(const uint8_t *data, uint8_t *key, uint8_t *rseed, uint32_t numblock);
void encrypt_cuda_io(const uint8_t *inparray, uint8_t *outarray, uint8_t *key, uint8_t *rseed, uint32_t numblock);
