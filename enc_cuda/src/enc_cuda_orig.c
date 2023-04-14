#include "enc_cuda/enc_cuda.h"
#include "helpers.h"
#include "aes_cpu.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <glib.h>

// for aes_set_key
#include <dolbeau/aes_scalar.h>

// For RTLD_NEXT
#include <dlfcn.h>
// For dirname
#include <libgen.h>



// Internal type passed to the user as a CUdeviceptr pointer.
// Wraps a CUdeviceptr, and associates it with two bounce buffers
// (host and device sides)
struct device_buf_with_bb {
	CUdeviceptr dptr; //< device buffer
	CUdeviceptr dbb; //< device bounce buffer
	void * hbb; //< host bounce buffer
};

// Global device-side state used for encryption:
// - the GPU AES-CTR cipher function
// - the (diagonilized) subkeys, and the current counter value
// - precomputed AES tables, copied once to the device
static CUfunction aes_ctr_dolbeau;
static CUdeviceptr d_aes_erdk, d_IV;
static unsigned char h_key[33], h_IV[33];
static CUdeviceptr dFT0, dFT1, dFT2, dFT3, dFSb;

// Recover the original CUDA function pointers
cu_memalloc_func_t * cu_memalloc;
cu_memfree_func_t * cu_memfree;
cu_memcpy_d_to_h_func_t * cu_memcpy_dh;
cu_memcpy_h_to_d_func_t * cu_memcpy_hd;


static int get_lib_load_path(char * load_path, size_t load_path_buflen)
{
    HERE;
    Dl_info info;
    if (dladdr(cuda_enc_setup, &info) == 0)
    {
        DEBUG_PRINTF("dladdr failed\n");
        return EXIT_FAILURE;
    }
    
    size_t len = strlen(info.dli_fname) + 1;
    char load_name[256] = {0};
    if(len > sizeof(load_name)) {
        DEBUG_PRINTF("Absolute path of library is too long\n");
        return EXIT_FAILURE;
    }
    memcpy(load_name, info.dli_fname, len);
    
    
    char * dname = dirname(load_name);
    size_t dname_len = strlen(dname) + 1;
    if(dname_len > load_path_buflen)
    if(len > sizeof(load_name)) {
        DEBUG_PRINTF("Absolute path of library directory is too long\n");
        return EXIT_FAILURE;
    }

    memcpy(load_path, dname, dname_len);
    
    return EXIT_SUCCESS;
}

__attribute__((visibility("default")))
CUresult cuda_enc_setup(char *key, char *iv)
{
    HERE;
    CUresult ret;

    DEBUG_PRINTF("cuda_enc_setup\n");


    DEBUG_PRINTF("obtain the function pointers to the CUDA functions to interpose\n");

    cu_memalloc = dlsym(RTLD_NEXT, "cuMemAlloc");
    assert(cu_memalloc != NULL);

    cu_memfree = dlsym(RTLD_NEXT, "cuMemFree");
    assert(cu_memfree != NULL);

    cu_memcpy_dh = dlsym(RTLD_NEXT, "cuMemcpyDtoH");
    assert(cu_memcpy_dh != NULL);

    cu_memcpy_hd = dlsym(RTLD_NEXT, "cuMemcpyHtoD");
    assert(cu_memcpy_hd != NULL);


    // Get shared library path:

    char load_path[256];
    if(get_lib_load_path(load_path, sizeof(load_path) != EXIT_SUCCESS))
    {
        DEBUG_PRINTF("Failed to get library load path\n");
        ret = CUDA_ERROR_UNKNOWN;
        goto cuda_err;
    }

    DEBUG_PRINTF("Loaded from path = %s\n", load_path);

    char module_name[256];
    snprintf(module_name, sizeof(module_name), "%s/../share/enc_cuda/aes_gpu.cubin", load_path);
    DEBUG_PRINTF("load module %s\n", module_name);

    /* Load ciper function */
    CUmodule module;
    ret = cuModuleLoad(&module, module_name);
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    HERE;
    ret = cuModuleGetFunction(&aes_ctr_dolbeau, module, "aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal");
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    HERE;
    /* Setup keys, initial counter value and precomputed tables */

    // ---------
    // Memory allocation

    DEBUG_PRINTF("mem alloc: tables\n");

    // tables
    if ((ret = cu_memalloc(&dFT0, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memalloc(&dFT1, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memalloc(&dFT2, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memalloc(&dFT3, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memalloc(&dFSb, 1024)) != CUDA_SUCCESS)
        goto cuda_err;

    DEBUG_PRINTF("mem alloc: iv and key\n");

    // keys and IV
    size_t maxb = 16;
    if ((ret = cu_memalloc(&d_aes_erdk, 256)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memalloc(&d_IV, 16 * maxb)) != CUDA_SUCCESS)
        goto cuda_err;

    // --------------
    // Initilization

    DEBUG_PRINTF("init: tables\n");

    // Tables
    if ((ret = cu_memcpy_hd(dFT0, FT0, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memcpy_hd(dFT1, FT1, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memcpy_hd(dFT2, FT2, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memcpy_hd(dFT3, FT3, 1024)) != CUDA_SUCCESS)
        goto cuda_err;
    if ((ret = cu_memcpy_hd(dFSb, FSb, 1024)) != CUDA_SUCCESS)
        goto cuda_err;

    DEBUG_PRINTF("init: keys\n");

    // Diagonalize subkeys
    uint32_t aes_edrk[64];
    uint32_t aes_edrk_diag[64];
    aes_set_key((const unsigned int *)key, aes_edrk);
    {
        /* ** diagonalization of subkeys */
        /* first four are not diagonalized */
        for (int i = 0; i < 4; i++)
        {
            aes_edrk_diag[i] = aes_edrk[i];
        }
        /* then all but last four are */
        for (int i = 4; i < 56; i += 4)
        {
            diag1cpu(aes_edrk_diag + i, aes_edrk + i);
        }
        /* last four */
        for (int i = 56; i < 64; i++)
        {
            aes_edrk_diag[i] = aes_edrk[i];
        }
    }

    // move subkeys to device
    ret = cu_memcpy_hd(d_aes_erdk, aes_edrk_diag, sizeof(aes_edrk_diag));
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    // move initial counter to device
    ret = cu_memcpy_hd(d_IV, iv, sizeof(iv));
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    // save key and IV on CPU
    DEBUG_PRINTF("init: save key and IV for CPU\n");
    assert(sizeof(h_IV) == (strlen(iv) + 1));
    assert(sizeof(h_key) == (strlen(key) + 1));

    memcpy(h_key, key, sizeof(h_key));
    memcpy(h_IV, iv, sizeof(h_IV));

    DEBUG_PRINTF("cuda_enc_init done\n");

    ret = CUDA_SUCCESS;
    goto cleanup;

cuda_err:
    CUDA_PRINT_ERROR(ret);
cleanup:
    return ret;
}

__attribute__((visibility("default")))
CUresult cuMemAlloc(CUdeviceptr *dptr, unsigned int bytesize)
{
    HERE;
    DEBUG_PRINTF("=========================\n");
    assert(cu_memalloc != NULL);

    CUresult ret;

    DEBUG_PRINTF("enc_cuMemAlloc\n");

    // host side structure to hold the actual device pointer, and the pointer
    // to the two bounce buffers
    struct device_buf_with_bb *data = malloc(sizeof(struct device_buf_with_bb));

    // bounce buffer sizes
    // the enc/dec routines will work on multiples of the GPU_BLOCK_SIZE,
    unsigned int bb_bytesize = ROUND_UP(bytesize, GPU_BLOCK_SIZE);

    // allocate host bounce bufffer
    data->hbb = malloc(bb_bytesize);
    if (data->hbb == NULL)
    {
        ret = CUDA_ERROR_OPERATING_SYSTEM;
        goto err;
    }

    // allocate device bounce buffer
    if ((ret = cu_memalloc(&data->dbb, bb_bytesize)) != CUDA_SUCCESS)
        goto cuda_err;

    // allocate normal device buffer. Also bb_bytesize because
    // encryption will read past the end of data!
    if ((ret = cu_memalloc(&data->dptr, bb_bytesize)) != CUDA_SUCCESS)
        goto cuda_err;

    *dptr = (CUdeviceptr)data;

    ret = CUDA_SUCCESS;
    goto cleanup;

cuda_err:
    CUDA_PRINT_ERROR(ret);
err:
cleanup:
    return ret;
}

__attribute__((visibility("default")))
CUresult cuMemFree(CUdeviceptr dptr)
{
    HERE;
    DEBUG_PRINTF("=========================\n");
    assert(cu_memfree != NULL);
    
    CUresult ret;

    DEBUG_PRINTF("enc_cuFree\n");

    struct device_buf_with_bb *data = (struct device_buf_with_bb *)dptr;

    HERE;
    HERE;
    // free normal device buffer
    if ((ret = cu_memfree(data->dptr)) != CUDA_SUCCESS)
        goto cuda_err;

    HERE;

    // free device bounce buffer
    if ((ret = cu_memfree(data->dbb)) != CUDA_SUCCESS)
        goto cuda_err;

    HERE;

    // free the host side bounce buffer
    free(data->hbb);

    // free the wrapper data structure
    free(data);

    ret = CUDA_SUCCESS;
    goto cleanup;

cuda_err:
    CUDA_PRINT_ERROR(ret);
err:
cleanup:
    return ret;    
}


// /!\ here dst and src are REAL CUdeviceptr, and not pointers to the wrapper
static CUresult aes_265_ctr_gpu(CUdeviceptr dst, CUdeviceptr src, unsigned int bb_buflen)
{
    HERE;
    // How many GPU blocks = batch of AES blocks?
    assert((bb_buflen & GPU_BLOCK_MASK) == 0);
    int nfullgpuaesblock = bb_buflen / GPU_BLOCK_SIZE;

    // gridsize
    int gx, gy, gz;
    // blocksize
    int bx, by, bz;

    gy = gz = 1;
    gx = nfullgpuaesblock;
    while (gx >= 65536)
    {
        gx /= 2;
        gy *= 2;
    }
    nfullgpuaesblock = gx * gy;

    by = bz = 1;
    bx = 256;

    HERE;
    // we don't want to have any leftover to process on the host!
    size_t dataleft = bb_buflen - (nfullgpuaesblock * GPU_BLOCK_SIZE);
    assert(dataleft == 0);

    // How many AES blocks in total?
    int nfullaesblock = 256 * nfullgpuaesblock;

    void *kernel_args[] = {
        &src, &dst, // in, out
        &d_aes_erdk,             // diagonalized subkeys
        &nfullaesblock,
        &dFT0, &dFT1, &dFT2, &dFT3, &dFSb, &d_IV};

    HERE;
    // dynamic memory. XXX: random value here! would 0 work ?
    size_t sharedMemBytes = 64;

    HERE;
    return cuLaunchKernel(
        aes_ctr_dolbeau,
        gx, gy, gz,
        bx, by, bz,
        sharedMemBytes,
        0, // default stream
        kernel_args,
        NULL);
}


__attribute__((visibility("default")))
CUresult cuMemcpyHtoD(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount)
{
    HERE;
    DEBUG_PRINTF("=========================\n");
    assert(cu_memcpy_hd != NULL);

    CUresult ret;

    struct device_buf_with_bb *data = (struct device_buf_with_bb *)dstDevice;

    DEBUG_PRINTF("enc_cuMemcpyHtoD\n");


    // XXX: here we encrypt just the buffer, but decrypt
    //  buffer + padding on the device, then truncate. This works
    //  because there is no authentication, but won't with GCM!
    //  We need to also encrypt the padding that will be decrypted.
    //  Possible using the openssl interface directly (update twice)

    unsigned int bb_buflen = ROUND_UP(ByteCount, GPU_BLOCK_SIZE);

    DEBUG_PRINTF("encrypt host bounce buffer\n");



    // encrypt source to host bounce buffer
    int clen;
    if (aes256_ctr_encrypt_openssl(
            data->hbb, &clen,   // c
            srcHost, ByteCount, // m
            h_IV, h_key) != EXIT_SUCCESS)
    {
        ret = CUDA_ERROR_UNKNOWN;
        goto cleanup;
    }



    // we can't have a ciphertext longer than our bounce buffer!
    assert(clen <= bb_buflen);

    // copy encrypted payload to device
    DEBUG_PRINTF("copy bounce buffer on device\n");

    ret = cu_memcpy_hd(data->dbb, data->hbb, bb_buflen);
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    // decrypt on device to destination
    DEBUG_PRINTF("decrypt on device from bounce buffer to destination\n");

    // wait for all memory to be on device
    cuCtxSynchronize();

    ret = aes_265_ctr_gpu(data->dptr, data->dbb, bb_buflen);
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    ret = CUDA_SUCCESS;
    goto cleanup;

cuda_err:
    CUDA_PRINT_ERROR(ret);
cleanup:
    return ret;
}


__attribute__((visibility("default")))
CUresult cuMemcpyDtoH(void *dstHost, CUdeviceptr srcDevice, unsigned int ByteCount)
{
    HERE;
    DEBUG_PRINTF("=========================\n");
    CUresult ret;

    assert(cu_memcpy_dh != NULL);

    struct device_buf_with_bb *data = (struct device_buf_with_bb *)srcDevice;

    DEBUG_PRINTF("enc_cuMemcpyDtoH\n");

    unsigned int bb_buflen = ROUND_UP(ByteCount, GPU_BLOCK_SIZE);

    // encrypt on device
    DEBUG_PRINTF("encrypt on device to bounce buffer\n");

    HERE;
    ret = aes_265_ctr_gpu(data->dbb, data->dptr, bb_buflen);
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    HERE;
    DEBUG_PRINTF("copy to host\n");

    // copy from device to host bounce buffer
    if((ret = cu_memcpy_dh(data->hbb, data->dbb, bb_buflen)) != CUDA_SUCCESS)
        goto cuda_err;

    DEBUG_PRINTF("decrypt on host from bounce buffer to destination\n");

    // decrypt on host from bounce buffer
    int mlen;
    if(aes256_ctr_decrypt_openssl(
        dstHost, &mlen,
        data->hbb, bb_buflen,
        h_IV, h_key 
    ) != EXIT_SUCCESS)
    {
        ret = CUDA_ERROR_UNKNOWN;
        goto cleanup;
    }



    ret = CUDA_SUCCESS;
    goto cleanup;

cuda_err:
    CUDA_PRINT_ERROR(ret);
cleanup:
    return ret;

}