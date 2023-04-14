#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#include <cuda.h>
}
#else
#include <cuda.h>
#endif
#include "util.h"

static char static_key[] = "0123456789abcdeF0123456789abcdeF";
static char static_iv[] = "12345678876543211234567887654321";

CUresult cuda_driver_api_init(CUcontext *pctx, CUmodule *pmod, const char *f)
{
	CUresult res;
	CUdevice dev;

	res = cuInit(0);
	if (res != CUDA_SUCCESS) {
		printf("cuInit failed: res = %lu\n", (unsigned long)res);
		return res;
	}

	res = cuDeviceGet(&dev, 0);
	if (res != CUDA_SUCCESS) {
		printf("cuDeviceGet failed: res = %lu\n", (unsigned long)res);
		return res;
	}

	res = cuCtxCreate(pctx, 0, dev);
	if (res != CUDA_SUCCESS) {
		printf("cuCtxCreate failed: res = %lu\n", (unsigned long)res);
		return res;
	}
	
	res = cuModuleLoad(pmod, f);
	if (res != CUDA_SUCCESS) {
		printf("cuModuleLoad() failed\n");
		cuCtxDestroy(*pctx);
		return res;
	}

    /* load encryption */
    #ifdef ENC_CUDA
    {
        CUresult ret = cuda_enc_setup(static_key, static_iv);
        if (ret != CUDA_SUCCESS) {
          fprintf(stderr, "cuda_enc_setup failed\n");
          return ret;
        }
  }
    #endif

    return CUDA_SUCCESS;
}

CUresult cuda_driver_api_exit(CUcontext ctx, CUmodule mod)
{
	CUresult res;

    HERE;
    #if 0
	res = cuModuleUnload(mod);
	if (res != CUDA_SUCCESS) {
		printf("cuModuleUnload failed: res = %lu\n", (unsigned long)res);
		return res;
	}
    #endif
    HERE;

    #if 0
	res = cuCtxDestroy(ctx);
	if (res != CUDA_SUCCESS) {
		printf("cuCtxDestroy failed: res = %lu\n", (unsigned long)res);
		return res;
	}
    #endif
    HERE;

	return CUDA_SUCCESS;
}

void time_measure_start(struct timeval *tv)
{
	gettimeofday(tv, NULL);
}

void time_measure_end(struct timeval *tv)
{
	struct timeval tv_now, tv_diff;
	double d;

	gettimeofday(&tv_now, NULL);
	tvsub(&tv_now, tv, &tv_diff);

	d = (double) tv_diff.tv_sec * 1000.0 + (double) tv_diff.tv_usec / 1000.0;
	printf("Time (Memory Copy and Launch) = %f (ms)\n", d);
}

void probe_time_start(struct timestamp *ts)
{
    gettimeofday(&ts->start, NULL);
}

float probe_time_end(struct timestamp *ts)
{
    struct timeval tv;
    gettimeofday(&ts->end, NULL);
	tvsub(&ts->end, &ts->start, &tv);
	return (tv.tv_sec * 1000.0 + (float) tv.tv_usec / 1000.0);
}
