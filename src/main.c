#include <stdio.h>
#include <stdlib.h>

#include <cuda.h>

int main(int argc, char ** argv)
{
    CUresult res;


	res = cuInit(0);
	if (res != CUDA_SUCCESS) {
		printf("cuInit failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

	CUdevice dev;
	res = cuDeviceGet(&dev, 0);
	if (res != CUDA_SUCCESS) {
		printf("cuDeviceGet failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

	CUcontext ctx;
	res = cuCtxCreate(&ctx, 0, dev);
	if (res != CUDA_SUCCESS) {
		printf("cuCtxCreate failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

    char path[] = "src";
    char fname[256] = {0};
    CUmodule module;
	snprintf(fname, sizeof(fname), "%s/kernel.cubin", path);
	res = cuModuleLoad(&module, fname);
	if (res != CUDA_SUCCESS) {
		printf("cuModuleLoad() failed\n");
		return -1;
	}

    CUfunction function;
	res = cuModuleGetFunction(&function, module, "mul");
	if (res != CUDA_SUCCESS) {
		printf("cuModuleGetFunction() failed\n");
		return -1;
	}


	/* initialize A[] & B[] */
    size_t n = 3;
    float *a = (float *) malloc (n*n * sizeof(float));
	float *b = (float *) malloc (n*n * sizeof(float));
	float *c = (float *) malloc (n*n * sizeof(float));

	for (size_t i = 0; i < n; i++) {
		for(size_t j = 0; j < n; j++) {
			size_t idx = i * n + j;
			a[idx] = i + 0.1;
			b[idx] = i + 0.1;
		}
	}


	CUdeviceptr a_dev, b_dev, c_dev;
	res = cuMemAlloc(&a_dev, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemAlloc (a) failed\n");
		return -1;
	}
	/* b[] */
	res = cuMemAlloc(&b_dev, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemAlloc (b) failed\n");
		return -1;
	}
	/* c[] */
	res = cuMemAlloc(&c_dev, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemAlloc (c) failed\n");
		return -1;
	}

	/* upload a[] and b[] */
	res = cuMemcpyHtoD(a_dev, a, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemcpyHtoD (a) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}
	res = cuMemcpyHtoD(b_dev, b, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemcpyHtoD (b) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}


	unsigned int block_x = n < 16 ? n : 16;
	unsigned int block_y = n < 16 ? n : 16;
	unsigned int grid_x = n / block_x;
	if (n % block_x != 0)
		grid_x++;
	unsigned int grid_y = n / block_y;
	if (n % block_y != 0)
		grid_y++;


    unsigned int sharedMemBytes = 40;
    /* */

    void * kernel_args[] = {&a_dev, &b_dev, &c_dev, &n};
    res = cuLaunchKernel(
        function,
        grid_x, grid_y, 1,
        block_x, block_y, 1,
        sharedMemBytes,
        0,
        kernel_args,
        NULL
    );

	cuCtxSynchronize();

	res = cuMemcpyDtoH(c, c_dev, n*n * sizeof(float));
	if (res != CUDA_SUCCESS) {
		printf("cuMemcpyDtoH (c) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

    // print c[]
    printf("n=%zu\n", n);
	for (size_t i = 0; i < n; i++) {
		for(size_t j = 0; j < n; j++) {
			size_t idx = i * n + j;
			printf("%f ", c[idx]);
		}
        printf("\n");
	}
    
    // Free CUDA buffers
	res = cuMemFree(a_dev);
	if (res != CUDA_SUCCESS) {
		printf("cuMemFree (a) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}
	res = cuMemFree(b_dev);
	if (res != CUDA_SUCCESS) {
		printf("cuMemFree (b) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}
	res = cuMemFree(c_dev);
	if (res != CUDA_SUCCESS) {
		printf("cuMemFree (c) failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

    // unload module
	res = cuModuleUnload(module);
	if (res != CUDA_SUCCESS) {
		printf("cuModuleUnload failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

    // destroy contet
	res = cuCtxDestroy(ctx);
	if (res != CUDA_SUCCESS) {
		printf("cuCtxDestroy failed: res = %lu\n", (unsigned long)res);
		return -1;
	}

    // free host buffers
	free(a);
	free(b);
	free(c);

    return 0;
}