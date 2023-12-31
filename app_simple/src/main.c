#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <enc_cuda/enc_cuda.h>


#define GPU_BLOCK_SIZE (uint64_t)(256 * 16)

#define CUDA_PRINT_ERROR(e) \
	cuda_print_error(__FILE__, __LINE__, e)

static inline void cuda_print_error(char * file, int line, CUresult e)
{
	fprintf(stderr, "(%s:%d), error %d\n", file, line, e);
}

static unsigned char static_key[] = "0123456789abcdeF0123456789abcdeF";
static unsigned char static_iv[] = "12345678876543211234567887654321";


int main(int argc, char ** argv)
{
    CUresult ret;

	ret = cuInit(0);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuInit failed\n");
		goto cuda_err;
	}

	CUdevice dev;
	ret = cuDeviceGet(&dev, 0);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuDeviceGet failed\n");
		goto cuda_err;
	}

	CUcontext ctx;
	ret = cuCtxCreate(&ctx, 0, dev);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuCtxCreate failed\n");
		goto cuda_err;
	}

	ret = cuda_enc_setup(static_key, static_iv);
	if(ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuda_enc_setup failed\n");
		goto cuda_err;
	}

	// memory for a[]
    size_t n = 2 * GPU_BLOCK_SIZE;
    unsigned char * a = malloc (n);
	unsigned char * a_res = malloc(n);

	CUdeviceptr a_dev;
	ret = cuMemAlloc(&a_dev, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuMemAlloc a failed\n");
		goto cuda_err;
	}

	// initialize a[]
	for (size_t i = 0; i < n; i++) {
		a[i] = (unsigned char)(i % 10);
	}

	/* upload a[] */
	ret = cuMemcpyHtoD(a_dev, a, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuMemcpyHtoD a failed\n");
		goto cuda_err;
	}
	
	ret = cuMemcpyDtoH(a_res, a_dev, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuMemcpyDtoH a_dev failed\n");
		goto cuda_err;
	}

    // print a_res[]
    printf("n=%zu\n", n);
	for (size_t i = 0; i < 5; i++) {
		unsigned char c = (unsigned char)(i % 10);
		printf("%u ", a_res[i]);
		//assert(a_res[i] == c);
	}
	printf("\n");



    // Free CUDA buffers
	ret = cuMemFree(a_dev);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuMemFree failed\n");
		goto cuda_err;
	}

    // destroy contet
	ret = cuCtxDestroy(ctx);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuCtxDestroy failed\n");
		goto cuda_err;
	}

    // free host buffers
	free(a_res);
	free(a);

	goto cleanup;

cuda_err:
	CUDA_PRINT_ERROR(ret);
	return 1;
cleanup:
    return 0;
}