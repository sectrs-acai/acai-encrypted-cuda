#pragma once

#include <cuda.h>
#include <stdio.h>

// Only for powers of two
#define ROUND_DOWN(x, s) (((uint64_t)(x)) & (~((uint64_t)s-1)))
#define ROUND_UP(x, s) ( (((uint64_t)(x)) + (uint64_t)s-1)  & (~((uint64_t)s-1)) ) 

#define GPU_BLOCK_SIZE (uint64_t)(256 * 16)
#define GPU_BLOCK_MASK (GPU_BLOCK_SIZE - 1)

#define HERE printf("[debug] %s/%s: %d\n", __FILE__, __FUNCTION__, __LINE__)

#define CUDA_PRINT_ERROR(e) \
	cuda_print_error(__FILE__, __LINE__, e)

#ifndef NDEBUG
#define DEBUG_PRINTF(fmt...) fprintf(stderr, fmt)
#else
#define DEBUG_PRINTF(fmt...)
#endif

static inline void cuda_print_error(char * file, int line, CUresult e)
{
	fprintf(stderr, "(%s:%d), error %d\n", file, line, e);
}

#define PRINT_ERROR(fmt, ...) \
fprintf(stderr, "[err] %s/%s/%d: " fmt, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

