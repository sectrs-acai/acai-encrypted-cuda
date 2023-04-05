#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <cuda.h>


#include <dolbeau/aes_scalar.h> // for aes_set_key
// #include <dolbeau/aes_gpu.h>



// Only for powers of two
#define ROUND_DOWN(x, s) (((uint64_t)(x)) & (~((uint64_t)s-1)))
#define ROUND_UP(x, s) ( (((uint64_t)(x)) + (uint64_t)s-1)  & (~((uint64_t)s-1)) ) 


#define GPU_BLOCK_SIZE (uint64_t)(256 * 16)
#define GPU_BLOCK_MASK (GPU_BLOCK_SIZE - 1)

#define DEBUG_PRINTF(fmt...) fprintf(stderr, fmt)

void cuda_print_error(char * file, int line, CUresult e)
{
	char * n, m;
	//cuGetErrorName(e, &n);
	//cuGetErrorString(e, &m);
	fprintf(stderr, "(%s:%d), error %d\n", file, line, e);
}

#define CUDA_PRINT_ERROR(e) \
	cuda_print_error(__FILE__, __LINE__, e)


typedef struct {
	CUdeviceptr dptr; //< device buffer
	CUdeviceptr dbb; //< device bounce buffer
	void * hbb; //< host bounce buffer
} enc_CUdeviceptr;

CUresult enc_cuMemAlloc(enc_CUdeviceptr *dptr, unsigned int bytesize);
CUresult enc_cuMemFree(enc_CUdeviceptr dptr);
CUresult enc_cuMemcpyDtoH(void *dstHost, enc_CUdeviceptr srcDevice, unsigned int ByteCount);
CUresult enc_cuMemcpyHtoD(enc_CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);



static unsigned char static_key[] = "0123456789abcdeF";
static unsigned char static_iv[] = "1234567887654321";

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int openssl_setup(void)
{
	DEBUG_PRINTF("openssl_setup\n");
	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	return 0;
}

int openssl_cleanup(void)
{
	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	return 0;
}



static CUfunction aes_ctr_dolbeau;
static CUdeviceptr d_aes_erdk, d_IV;
static CUdeviceptr dFT0, dFT1, dFT2, dFT3, dFSb;
CUresult cuda_enc_setup(char * key, char * iv)
{
	CUresult ret;

	DEBUG_PRINTF("cuda_enc_setup\n");


	//openssl_setup();

	DEBUG_PRINTF("load module\n");

	#if 0

	/* Load ciper function */
	CUmodule module;
	ret = cuModuleLoad(&module, "test");
	if (ret != CUDA_SUCCESS) {
		goto cuda_err;
	}

	ret = cuModuleGetFunction(&aes_ctr_dolbeau, module, "aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal");
	if (ret != CUDA_SUCCESS) {
		goto cuda_err;
	}

	/* Setup keys, initial counter value and precomputed tables */

	// ---------
	// Memory allocation
	#endif

	DEBUG_PRINTF("mem alloc: tables\n");


	// tables
	if((ret = cuMemAlloc(&dFT0, 1024)) != CUDA_SUCCESS) goto cuda_err;
	if((ret = cuMemAlloc(&dFT1, 1024)) != CUDA_SUCCESS) goto cuda_err;
	if((ret = cuMemAlloc(&dFT2, 1024)) != CUDA_SUCCESS) goto cuda_err;
	if((ret = cuMemAlloc(&dFT3, 1024)) != CUDA_SUCCESS) goto cuda_err;
	if((ret = cuMemAlloc(&dFSb, 1024)) != CUDA_SUCCESS) goto cuda_err;

	DEBUG_PRINTF("mem alloc: iv and key\n");

	// keys and IV
	size_t maxb = 16;
	if((ret = cuMemAlloc(&d_aes_erdk, 256)) != CUDA_SUCCESS) goto cuda_err;;
	if((ret = cuMemAlloc(&d_IV, 16*maxb)) != CUDA_SUCCESS) goto cuda_err;;

	// --------------
	// Initilization

	DEBUG_PRINTF("init: tables\n");


	// Tables
  	if((ret = cuMemcpyHtoD(dFT0, FT0, 1024)) != CUDA_SUCCESS) goto cuda_err;
  	if((ret = cuMemcpyHtoD(dFT1, FT1, 1024)) != CUDA_SUCCESS) goto cuda_err;
  	if((ret = cuMemcpyHtoD(dFT2, FT2, 1024)) != CUDA_SUCCESS) goto cuda_err;
  	if((ret = cuMemcpyHtoD(dFT3, FT3, 1024)) != CUDA_SUCCESS) goto cuda_err;
  	if((ret = cuMemcpyHtoD(dFSb, FSb, 1024)) != CUDA_SUCCESS) goto cuda_err;

	DEBUG_PRINTF("init: keys\n");


	// Diagonalize subkeys
	uint32_t aes_edrk[64];
	uint32_t aes_edrk_diag[64];
	aes_set_key((const unsigned int*)key, aes_edrk);
	{
		/* ** diagonalization of subkeys */
		/* first four are not diagonalized */
		for (int i = 0 ; i < 4 ; i++) {
			aes_edrk_diag[i] = aes_edrk[i];
		}
		/* then all but last four are */
		for (int i = 4 ; i < 56 ; i+= 4) {
			diag1cpu(aes_edrk_diag+i, aes_edrk+i);
		}
		/* last four */
		for (int i = 56 ; i < 64 ; i++) {
			aes_edrk_diag[i] = aes_edrk[i];
		}
	}

	// move subkeys to device
	ret = cuMemcpyHtoD(d_aes_erdk, aes_edrk_diag, 256);
	if (ret != CUDA_SUCCESS)
		goto cuda_err;

	// move initial counter to device
	ret = cuMemcpyHtoD(d_IV, iv, 16);
	if (ret != CUDA_SUCCESS)
		goto cuda_err;

	DEBUG_PRINTF("cuda_enc_init done\n");

	ret = CUDA_SUCCESS;
	goto cleanup;

cuda_err:
	CUDA_PRINT_ERROR(ret);
cleanup:
	return ret;
}

/* AES-256-CTR mode encryption. */
int aes256_ctr_encrypt_openssl(
  unsigned char *c,int *clen,
  const unsigned char *m, int mlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
	int ret = EXIT_FAILURE;

	DEBUG_PRINTF("aes256_ctr_encrypt_openssl\n");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
    if (ctx == NULL || cipher == NULL)
        goto openssl_err;

	if(EVP_EncryptInit_ex2(ctx, cipher, k, npub, NULL) != 1)
		goto openssl_err;
	
	// get/set params if necessary, eg IVLEN 
  	
	// no AD yet
	// if (EVP_EncryptUpdate(ctx, 0, &outlen, ad,adlen) != 1) goto err;
	
	// encrypt m into ciphertext c
	if (EVP_EncryptUpdate(ctx, c, clen, m, mlen) != 1)
		goto openssl_err;
	
	// add trailing padding
	if (EVP_EncryptFinal_ex(ctx, c, clen) != 1)
		goto openssl_err; 

	ret = EXIT_SUCCESS;
	goto cleanup;

openssl_err:
	ERR_print_errors_fp(stderr);
cleanup:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}


int aes256_ctr_decrypt_openssl(
  unsigned char *m, int *mlen,
  const unsigned char *c, int clen,
  const unsigned char *npub,
  const unsigned char *k
)
{
	int ret = EXIT_FAILURE;


	DEBUG_PRINTF("aes256_ctr_decrypt_openssl\n");


	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
    if (ctx == NULL || cipher == NULL)
        goto openssl_err;

	if(EVP_DecryptInit_ex2(ctx, cipher, k, npub, NULL) != 1)
		goto openssl_err;

	// get/set params if necessary, eg IVLEN and TAG
	
	// encrypt m into ciphertext c
  	if (EVP_DecryptUpdate(ctx, m, mlen, c, clen) != 1)
		goto openssl_err; 
	
	// add trailing padding
	if (EVP_DecryptFinal_ex(ctx, m, mlen) != 1)
		goto openssl_err; 

	ret = EXIT_SUCCESS;
	goto cleanup;

openssl_err:
	ERR_print_errors_fp(stderr);
cleanup:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

CUresult enc_cuMemAlloc(enc_CUdeviceptr *dptr, unsigned int bytesize)
{
	CUresult ret;

	DEBUG_PRINTF("enc_cuMemAlloc\n");


	// bounce buffer sizes
	// the enc/dec routines will work on multiples of the GPU_BLOCK_SIZE,
	unsigned int bb_bytesize = ROUND_UP(bytesize, GPU_BLOCK_SIZE);

	// allocate host bounce bufffer
	dptr->hbb = malloc(bb_bytesize);
	if(dptr->hbb == NULL) {
		ret = CUDA_ERROR_OPERATING_SYSTEM;
		goto err;
	}

	// allocate device bounce buffer
	if((ret = cuMemAlloc(&dptr->dbb, bb_bytesize)) != CUDA_SUCCESS)
		goto cuda_err;

	// allocate normal device buffer
	if((ret = cuMemAlloc(&dptr->dptr, bytesize)) != CUDA_SUCCESS)
		goto cuda_err;


	ret = CUDA_SUCCESS;
	goto cleanup;


openssl_err:
	ERR_print_errors_fp(stderr);
cuda_err:
	CUDA_PRINT_ERROR(ret);
err:
cleanup:
	return ret;
}

CUresult enc_cuMemcpyHtoD(enc_CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount)
{
	CUresult ret;

	DEBUG_PRINTF("enc_cuMemcpyHtoD\n");


	//XXX: here we encrypt just the buffer, but decrypt
	// buffer + padding on the device, then truncate. This works
	// because there is no authentication, but won't with GCM!
	// We need to also encrypt the padding that will be decrypted.
	// Possible using the openssl interface directly (update twice)

	unsigned int bb_buflen = ROUND_UP(ByteCount, GPU_BLOCK_SIZE);

	DEBUG_PRINTF("encrypt source to host bounce buffer\n");


	// encrypt source to host bounce buffer
	int clen;
	if(aes256_ctr_encrypt_openssl(
		dstDevice.hbb, &clen, // c
		srcHost, ByteCount, // m
		static_iv, static_key
	) != EXIT_SUCCESS)
	{
		ret = CUDA_ERROR_UNKNOWN;
		goto cleanup;
	}

	// we can't have a ciphertext longer than our bounce buffer!
	assert(clen <= bb_buflen);

	// copy encrypted payload to device
	DEBUG_PRINTF("copy encrypted payload to device\n");

	ret = cuMemcpyHtoD(dstDevice.dbb, dstDevice.hbb, bb_buflen);
	if(ret != CUDA_SUCCESS)
		goto cuda_err;


	// decrypt on device to destination
	DEBUG_PRINTF("decrypt on device to destination\n");


	// How many GPU blocks = batch of AES blocks?
	assert((bb_buflen & GPU_BLOCK_MASK) == 0);
	int nfullgpuaesblock = bb_buflen / GPU_BLOCK_SIZE;

	// gridsize
	int gx, gy, gz;
	// blocksize
	int bx, by, bz;
	
	gy = gz = 1;
	gx = nfullgpuaesblock;
	while (gx >= 65536) {
		gx /= 2;
		gy *= 2;
	}
	nfullgpuaesblock = gx * gy;

	by = bz = 1;
  	bx = 256;

	// we don't want to have any leftover to process on the host!
	size_t dataleft = bb_buflen - (nfullgpuaesblock * GPU_BLOCK_SIZE);
	assert(dataleft == 0);

	// How many AES blocks in total?
	int nfullaesblock = 256 * nfullgpuaesblock;

	void * kernel_args[] = {
		&dstDevice.dbb, &dstDevice.dptr, //in, out
		&d_aes_erdk, // diagonalized subkeys
		&nfullaesblock,
		&dFT0, &dFT1, &dFT2, &dFT3, &dFSb, &d_IV
	};

	// dynamic memory. XXX: random value here! would 0 work ?
	size_t sharedMemBytes = 64;
    
	// wait for all memory to be on device
	cuCtxSynchronize();
	
	ret = cuLaunchKernel(
        aes_ctr_dolbeau,
        gx, gy, gz,
        bx, by, bz,
        sharedMemBytes,
        0, // default stream
        kernel_args,
        NULL
    );
	if(ret != CUDA_SUCCESS)
		goto cuda_err;

	ret = CUDA_SUCCESS;
	goto cleanup;

cuda_err:
	CUDA_PRINT_ERROR(ret);
cleanup:
	return ret;
}


int main(int argc, char ** argv)
{
    CUresult ret;

	DEBUG_PRINTF("cuInit\n");
	ret = cuInit(0);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuInit failed\n");
		goto cuda_err;
	}

	DEBUG_PRINTF("cuInit\n");
	ret = cuda_enc_setup(static_key, static_iv);
	if(ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuda_enc_setup failed\n");
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



	// memory for a[]
    size_t n = 2 * GPU_BLOCK_SIZE;
    unsigned char * a = malloc (n);

	enc_CUdeviceptr a_dev;
	ret = enc_cuMemAlloc(&a_dev, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "enc_cuMemAlloc a failed\n");
		goto cuda_err;
	}

	// initialize a[]
	for (size_t i = 0; i < n; i++) {
		a[i] = (unsigned char)(i % 10);
	}

	/* upload a[] */
	ret = enc_cuMemcpyHtoD(a_dev, a, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "enc_cuMemcpyHtoD a failed\n");
		goto cuda_err;
	}

	// copy back to host
	// XXX do it with enc_ function !

	char * a_res = malloc(n);

	ret = cuMemcpyDtoH(a_res, a_dev.dptr, n);
	if (ret != CUDA_SUCCESS) {
		fprintf(stderr, "cuMemcpyDtoH a_dev failed\n");
		goto cuda_err;
	}

    // print a_res[]
    printf("n=%zu\n", n);
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)(i % 10);
		printf("%u ", a_res[i]);
		//assert(a_res[i] == c);
	}
	printf("\n");

#ifdef CLEANUP

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
#endif

	goto cleanup;

cuda_err:
	CUDA_PRINT_ERROR(ret);
	return 1;
cleanup:
    return 0;
}