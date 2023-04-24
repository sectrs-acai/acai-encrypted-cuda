#include "enc_cuda/enc_cuda.h"
#include "helpers.h"
#include "aes_cpu.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// for aes_set_key
#include <dolbeau/aes_scalar.h>

// For RTLD_NEXT
#include <dlfcn.h>
// For dirname
#include <libgen.h>
#include <glib.h>

/*
 * XXX Set to 1 to encrypt kernel params
 */
#define CU_ENCRYPT_KERNEL_PARAM 1

// Internal type passed to the user as a CUdeviceptr pointer.
// Wraps a CUdeviceptr, and associates it with two bounce buffers
// (host and device sides)
struct device_buf_with_bb {
    CUdeviceptr dev_ptr; //< device buffer
    CUdeviceptr dev_bb; //< device bounce buffer
    void *host_bb; //< host bounce buffer
};

// Global device-side state used for encryption:
// - the GPU AES-CTR cipher function
// - the (diagonilized) subkeys, and the current counter value
// - precomputed AES tables, copied once to the device
static CUfunction aes_ctr_dolbeau;
static CUdeviceptr d_aes_erdk, d_IV;
static unsigned char h_key[33], h_IV[33];
static CUdeviceptr dFT0, dFT1, dFT2, dFT3, dFSb;

// key: device mem pointer
static GHashTable *hash_alloc = NULL;

#if CU_ENCRYPT_KERNEL_PARAM
static GHashTable *hash_kernel_param = NULL;
/*
 * static max size for kernel parameters
 * to account for encryption overhead of kernel parameters
 */
#define KERNEL_PARAM_ENC_BUFFER_SIZE (ROUND_UP(0x2000, GPU_BLOCK_SIZE))
static CUdeviceptr kernel_param_dev_ptr = 0;
char *kernel_param_src_buf = NULL;
#endif

/*
 * Some benchmarks use cuModuleGetGlobal to obtain a global variable
 * which was not allocated with cuAllocMem function.
 * Hence, lookup in hash_alloc will fail.
 * We use cu_module_get_global_buffer_dev_ptr as dev buffer
 * to do dummy gpu encryption on.
 */
static CUdeviceptr cu_module_get_global_buffer_dev_ptr;
const static int cu_module_get_global_buffer_size = GPU_BLOCK_SIZE * 4;

// Recover the original CUDA function pointers
cu_memalloc_func_t *cu_memalloc;
cu_memfree_func_t *cu_memfree;
cu_memcpy_d_to_h_func_t *cu_memcpy_dh;
cu_memcpy_h_to_d_func_t *cu_memcpy_hd;
cu_launch_grid_t *cu_launch_grid;
cu_param_set_size_t *cu_param_set_size;

static int get_lib_load_path(char *load_path, size_t load_path_buflen)
{
    Dl_info info;
    if (dladdr(cuda_enc_setup, &info) == 0) {
        DEBUG_PRINTF("dladdr failed\n");
        return EXIT_FAILURE;
    }

    size_t len = strlen(info.dli_fname) + 1;
    char load_name[256] = {0};
    if (len > sizeof(load_name)) {
        DEBUG_PRINTF("Absolute path of library is too long\n");
        return EXIT_FAILURE;
    }
    memcpy(load_name, info.dli_fname, len);

    char *dname = dirname(load_name);
    size_t dname_len = strlen(dname) + 1;
    if (dname_len > load_path_buflen)
        if (len > sizeof(load_name)) {
            DEBUG_PRINTF("Absolute path of library directory is too long\n");
            return EXIT_FAILURE;
        }

    memcpy(load_path, dname, dname_len);

    return EXIT_SUCCESS;
}

__attribute__((visibility("default"))) CUresult cuda_enc_release()
{
    /*
     * XXX: Watch out,
     * free itself relies on some of the data to be freed
     */
    if (d_aes_erdk != 0) {
        cu_memfree(d_aes_erdk);
    }
    if (d_IV != 0) {
        cu_memfree(d_IV);
    }
    if (dFT0 != 0) {
        cu_memfree(dFT0);
    }
    if (dFT1 != 0) {
        cu_memfree(dFT1);
    }
    if (dFT2 != 0) {
        cu_memfree(dFT2);
    }
    if (dFT3 != 0) {
        cu_memfree(dFT3);
    }
    if (dFSb != 0) {
        cu_memfree(dFSb);
    }
    if (cu_module_get_global_buffer_dev_ptr != 0) {
        /* use cuMemFree not cu_memfree to delete bounce buffers */
        cuMemFree(cu_module_get_global_buffer_dev_ptr);
    }

    #if CU_ENCRYPT_KERNEL_PARAM
    if (kernel_param_dev_ptr != 0) {
        /* use cuMemFree not cu_memfree to delete bounce buffers */
        cuMemFree(kernel_param_dev_ptr);
        kernel_param_dev_ptr = 0;
    }
    if (kernel_param_src_buf != NULL) {
        free(kernel_param_src_buf);
    }
    if (hash_kernel_param != NULL) {
        g_hash_table_destroy(hash_kernel_param);
    }
    #endif

    if (hash_alloc != NULL) {
        g_hash_table_destroy(hash_alloc);
    }

    return CUDA_SUCCESS;
}

__attribute__((visibility("default")))
CUresult cuda_enc_setup(char *key, char *iv)
{
    CUresult ret;
    printf("enccuda\n");
    DEBUG_PRINTF("cuda_enc_setup\n");

    cu_memalloc = dlsym(RTLD_NEXT, "cuMemAlloc");
    assert(cu_memalloc != NULL);

    cu_memfree = dlsym(RTLD_NEXT, "cuMemFree");
    assert(cu_memfree != NULL);

    cu_memcpy_dh = dlsym(RTLD_NEXT, "cuMemcpyDtoH");
    assert(cu_memcpy_dh != NULL);

    cu_memcpy_hd = dlsym(RTLD_NEXT, "cuMemcpyHtoD");
    assert(cu_memcpy_hd != NULL);

    #if CU_ENCRYPT_KERNEL_PARAM
    cu_launch_grid = dlsym(RTLD_NEXT, "cuLaunchGrid");
    assert(cu_launch_grid != NULL);

    cu_param_set_size = dlsym(RTLD_NEXT, "cuParamSetSize");
    assert(cu_param_set_size != NULL);

    hash_kernel_param = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (hash_kernel_param == NULL) {
        ret = -1;
        PRINT_ERROR("hash_kernel_param failed to alloc\n");
        goto cuda_err;
    }
    #endif

    // Get shared library path:
    char load_path[256];
    if (get_lib_load_path(load_path, sizeof(load_path) != EXIT_SUCCESS)) {
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

    ret = cuModuleGetFunction(&aes_ctr_dolbeau,
                              module,
                              "aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal");
    if (ret != CUDA_SUCCESS)
        goto cuda_err;


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
    aes_set_key((const unsigned int *) key, aes_edrk);
    {
        /* ** diagonalization of subkeys */
        /* first four are not diagonalized */
        for (int i = 0; i < 4; i++) {
            aes_edrk_diag[i] = aes_edrk[i];
        }
        /* then all but last four are */
        for (int i = 4; i < 56; i += 4) {
            diag1cpu(aes_edrk_diag + i, aes_edrk + i);
        }
        /* last four */
        for (int i = 56; i < 64; i++) {
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

    DEBUG_PRINTF("inithash table\n");
    hash_alloc = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (hash_alloc == NULL) {
        ret = -1;
        goto cuda_err;
    }

    #if CU_ENCRYPT_KERNEL_PARAM
    /*
     * Allocate a memory region used to account
     * for kernel parameter encryption during kernel launch
     * Arguments cant be larger than KERNEL_PARAM_ENC_BUFFER_SIZE
     * XXX: use cuMemAlloc to allocate bounce buffer struct, must
     *      be after init of cuMemAlloc
     */
    ret = cuMemAlloc(&kernel_param_dev_ptr, KERNEL_PARAM_ENC_BUFFER_SIZE);
    if (ret != CUDA_SUCCESS) {
        PRINT_ERROR("cant allocate kernel_param_dev_ptr with size: %d\n",
                    KERNEL_PARAM_ENC_BUFFER_SIZE);
        goto cuda_err;
    }
    kernel_param_src_buf = malloc(KERNEL_PARAM_ENC_BUFFER_SIZE);
    if (kernel_param_src_buf == NULL) {
        PRINT_ERROR("kernel_param_src_buf failed to malloc\n");
        ret = CUDA_ERROR_OUT_OF_MEMORY;
        goto cuda_err;
    }
    #endif

    ret = cuMemAlloc(&cu_module_get_global_buffer_dev_ptr, cu_module_get_global_buffer_size);
    if (ret != CUDA_SUCCESS) {
        PRINT_ERROR("cant allocate cu_module_get_global_buffer_dev_ptr with size: %d\n",
                    cu_module_get_global_buffer_size);
        goto cuda_err;
    }

    DEBUG_PRINTF("cuda_enc_init done\n");

    ret = CUDA_SUCCESS;
    goto cleanup;

    cuda_err:
    CUDA_PRINT_ERROR(ret);
    cleanup:
    return ret;
}

__attribute__((visibility("default")))
CUresult cuMemAlloc(CUdeviceptr *dev_ptr, unsigned int bytesize)
{
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
    data->host_bb = malloc(bb_bytesize);
    if (data->host_bb == NULL) {
        ret = CUDA_ERROR_OPERATING_SYSTEM;
        goto err;
    }

    // allocate device bounce buffer
    if ((ret = cu_memalloc(&data->dev_bb, bb_bytesize)) != CUDA_SUCCESS)
        goto cuda_err;

    // allocate normal device buffer. Also bb_bytesize because
    // encryption will read past the end of data!
    if ((ret = cu_memalloc(&data->dev_ptr, bb_bytesize)) != CUDA_SUCCESS)
        goto cuda_err;

    *dev_ptr = data->dev_ptr;
    g_hash_table_insert(hash_alloc, (void *) *dev_ptr, data);

    ret = CUDA_SUCCESS;
    goto cleanup;

    cuda_err:
    CUDA_PRINT_ERROR(ret);
    err:
    cleanup:
    return ret;
}

__attribute__((visibility("default")))
CUresult cuMemFree(CUdeviceptr dev_ptr)
{
    assert(cu_memfree != NULL);
    CUresult ret;

    struct device_buf_with_bb *data =
        g_hash_table_lookup(hash_alloc, (const void *) dev_ptr);

    if (!data) {
        ret = CUDA_ERROR_NOT_FOUND;
        PRINT_ERROR("free: lookup failed for ptr %ld\n", dev_ptr);
        goto cuda_err;
    }

    // free normal device buffer
    if ((ret = cu_memfree(data->dev_ptr)) != CUDA_SUCCESS) {
        goto cuda_err;
    }

    // free device bounce buffer
    if ((ret = cu_memfree(data->dev_bb)) != CUDA_SUCCESS) {
        goto cuda_err;
    }

    // free the host side bounce buffer
    free(data->host_bb);

    g_hash_table_remove(hash_alloc, (const void *) dev_ptr);

    // free the wrapper data structure
    free(data);

    return CUDA_SUCCESS;

    cuda_err:
    CUDA_PRINT_ERROR(ret);
    return ret;
}

// /!\ here dst and src are REAL CUdeviceptr, and not pointers to the wrapper
static CUresult aes_265_ctr_gpu(CUdeviceptr dst, CUdeviceptr src, unsigned int bb_buflen)
{
    DEBUG_PRINTF("aes_265_ctr_gpu dst: %lx, src: %lx, s: %lx\n", dst, src, bb_buflen);

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

    void *kernel_args[] = {
        &src, &dst, // in, out
        &d_aes_erdk,             // diagonalized subkeys
        &nfullaesblock,
        &dFT0, &dFT1, &dFT2, &dFT3, &dFSb, &d_IV};


    // dynamic memory. XXX: random value here! would 0 work ?
    size_t sharedMemBytes = 64;

    return cuLaunchKernel(
        aes_ctr_dolbeau,
        gx, gy, gz,
        bx, by, bz,
        sharedMemBytes,
        0, // default stream
        kernel_args,
        NULL);
}


inline static CUresult do_cuMemcpyHtoD(CUdeviceptr dstDevice,
                         const void *srcHost,
                         unsigned int ByteCount,
                         struct device_buf_with_bb *data
)
{

    assert(cu_memcpy_hd != NULL);
    CUresult ret;

    CUdeviceptr dev_ptr = dstDevice;
    CUdeviceptr dev_bb = data->dev_bb;
    char *host_bb = data->host_bb;

    /*
     * XXX: The current dummy implementation accounts for the encryption
     * overhead but does not rely on encryption results.
     * We may later transfer encrypted payload once correctly working
     *
     * Host to Device:
     * - 1.) Host: Enc srcHost to dummy buffer
     * - 2.) Host: transfer unencrypted payload
     * - 3.) Dev: Decrypt (unencrypted payload) to dummy buffer
     */

    // XXX: here we encrypt just the buffer, but decrypt
    //  buffer + padding on the device, then truncate. This works
    //  because there is no authentication, but won't with GCM!
    //  We need to also encrypt the padding that will be decrypted.
    //  Possible using the openssl interface directly (update twice)
    unsigned int bb_buflen = ROUND_UP(ByteCount, GPU_BLOCK_SIZE);
    DEBUG_PRINTF("encrypt host bounce buffer\n");

    int clen;
    if (aes256_ctr_encrypt_openssl(
        host_bb, &clen,   // c
        srcHost, ByteCount, // m
        h_IV, h_key) != EXIT_SUCCESS) {
        ret = CUDA_ERROR_UNKNOWN;
        goto cuda_err;
    }
    assert(clen <= bb_buflen);

    DEBUG_PRINTF("copy bounce buffer on device\n");
    ret = cu_memcpy_hd(dev_ptr, srcHost, ByteCount);
    if (ret != CUDA_SUCCESS) {
        goto cuda_err;
    }

    DEBUG_PRINTF("decrypt on device from bounce buffer to destination\n");

    cuCtxSynchronize();

    // XXX: data->dev_bb contains the decrypted garbage
    ret = aes_265_ctr_gpu(dev_bb, dev_ptr, bb_buflen);
    if (ret != CUDA_SUCCESS) {
        goto cuda_err;
    }

    return CUDA_SUCCESS;

    cuda_err:
    CUDA_PRINT_ERROR(ret);
    return ret;

}


inline static CUresult do_cuMemcpyDtoH(
    void *dstHost,
    CUdeviceptr srcDevice,
    unsigned int ByteCount,
    struct device_buf_with_bb *data
)
{
    assert(cu_memcpy_hd != NULL);
    CUresult ret;
    unsigned int bb_buflen = ROUND_UP(ByteCount, GPU_BLOCK_SIZE);
    CUdeviceptr dev_ptr = srcDevice;
    CUdeviceptr dev_bb = data->dev_bb;
    const char *host_bb = data->host_bb;

    /*
    * XXX: The current dummy implementation accounts for the encryption
    * overhead but does not rely on encryption results.
    * We may later transfer encrypted payload once correctly working
    *
    * Device to Host:
    * - 1.) Dev: Encrypt data to dummy buffer
    * - 2.) Host: Decrypt garbage host buffer to dstHost
    * - 3.) Dev: transfer unencrypted payload
    *
    * Due to the dummy implementation we
    * switch 2 and 3. in order not to allocate an additional buffer.
    * This way we write to dstHost twice. Once garbage and 2nd the result.
    */
    ret = aes_265_ctr_gpu(dev_bb, dev_ptr, bb_buflen);
    if (ret != CUDA_SUCCESS)
        goto cuda_err;

    DEBUG_PRINTF("decrypt on host from bounce buffer to destination\n");
    cuCtxSynchronize();

    // decrypt on host from bounce buffer
    int mlen;
    if (aes256_ctr_decrypt_openssl(
        dstHost, &mlen,
        host_bb, ByteCount,
        h_IV, h_key
    ) != EXIT_SUCCESS) {
        ret = CUDA_ERROR_UNKNOWN;
        goto cuda_err;
    }

    if ((ret = cu_memcpy_dh(dstHost, dev_ptr, ByteCount)) != CUDA_SUCCESS) {
        goto cuda_err;
    }

    return CUDA_SUCCESS;

    cuda_err:
    CUDA_PRINT_ERROR(ret);
    return ret;
}

__attribute__((visibility("default")))
CUresult cuMemcpyDtoH(
    void *dstHost,
    CUdeviceptr srcDevice,
    unsigned int ByteCount)
{
    struct device_buf_with_bb *data;
    assert(cu_memcpy_dh != NULL);

    data = g_hash_table_lookup(hash_alloc, (const void *) srcDevice);
    if (!data) {
        /*
         * Workaround:
         * dstDevice was obtained with cuModuleGetGlobal
         * and not explicitly allocated. Use preallocated memory for encryption buffers.
         */
        data = g_hash_table_lookup(hash_alloc, (const void *) cu_module_get_global_buffer_dev_ptr);
        if (!data) {
            PRINT_ERROR("hash_alloc lookup failed for cu_module_get_global_buffer_dev_ptr \n");
            return CUDA_ERROR_NOT_FOUND;
        }
        if (ByteCount > cu_module_get_global_buffer_size) {
            PRINT_ERROR("req. size %d is too large. statically allocated: %d \n",
                        ByteCount, cu_module_get_global_buffer_size);
            return CUDA_ERROR_OUT_OF_MEMORY;
        }
    }
    return do_cuMemcpyDtoH(dstHost, srcDevice, ByteCount, data);
}

__attribute__((visibility("default")))
CUresult cuMemcpyHtoD(
    CUdeviceptr dstDevice,
    const void *srcHost,
    unsigned int ByteCount)
{
    assert(cu_memcpy_hd != NULL);
    struct device_buf_with_bb *data;

    data = g_hash_table_lookup(hash_alloc, (const void *) dstDevice);
    if (!data) {
        /*
         * Workaround:
         * dstDevice was obtained with cuModuleGetGlobal
         * and not explicitly allocated. Use preallocated memory for encryption buffers.
         */
        data = g_hash_table_lookup(hash_alloc, (const void *) cu_module_get_global_buffer_dev_ptr);
        if (!data) {
            PRINT_ERROR("hash_alloc lookup failed for cu_module_get_global_buffer_dev_ptr \n");
            return CUDA_ERROR_NOT_FOUND;
        }
        if (ByteCount > cu_module_get_global_buffer_size) {
            PRINT_ERROR("req. size %d is too large. statically allocated: %d \n",
                        ByteCount, cu_module_get_global_buffer_size);
            return CUDA_ERROR_OUT_OF_MEMORY;
        }
    }
    return do_cuMemcpyHtoD(dstDevice, srcHost, ByteCount, data);
}

#if CU_ENCRYPT_KERNEL_PARAM
__attribute__((visibility("default")))
CUresult cuParamSetSize(CUfunction hfunc, unsigned int numbytes)
{
    if (numbytes > KERNEL_PARAM_ENC_BUFFER_SIZE) {
        numbytes = KERNEL_PARAM_ENC_BUFFER_SIZE;
        PRINT_ERROR("cuParamSetSize size: %ud is larger than prealloced %d bytes\n",
                    numbytes,
                    KERNEL_PARAM_ENC_BUFFER_SIZE
        );
    }
    g_hash_table_insert(hash_kernel_param, hfunc,
                        GINT_TO_POINTER(ROUND_UP(numbytes, GPU_BLOCK_SIZE)));
    return cu_param_set_size(hfunc, numbytes);
}

static CUresult launch_encryption_overhead(
    CUfunction f,
    int grid_width,
    int grid_height)
{
    CUresult ret;
    struct device_buf_with_bb *data;
    unsigned char *host_bb = NULL;
    unsigned char *src_host = NULL;
    long byte_count;
    byte_count = (long) g_hash_table_lookup(hash_kernel_param, (const void *) f);
    if (!byte_count) {
        ret = CUDA_ERROR_NOT_FOUND;
        /*
         * possible that kernel has no params, ignore error
         */
        DEBUG_PRINTF("encoverhead: lookup failed for ptr %llx. Does kernel have args?\n", f);
        return ret;
    }
    data = g_hash_table_lookup(hash_alloc, (const void *) kernel_param_dev_ptr);
    if (!data) {
        ret = CUDA_ERROR_NOT_FOUND;
        PRINT_ERROR("g_hash_table_lookup failed for kernel param %llx\n", kernel_param_dev_ptr);
        return ret;
    }

    host_bb = data->host_bb;
    src_host = (unsigned char *) kernel_param_src_buf;

    /*
     * sync with prior launch
     */
    cuCtxSynchronize();

    /*
     * Dummy encryption to account for overhead
     */
    int clen;
    if (aes256_ctr_encrypt_openssl(
        host_bb, &clen,   // c
        src_host, byte_count, // m
        h_IV, h_key) != EXIT_SUCCESS) {
        ret = CUDA_ERROR_UNKNOWN;
        return ret;
    }
    assert(clen <= byte_count);

    ret = aes_265_ctr_gpu(data->dev_bb, data->dev_ptr, byte_count);
    if (ret != CUDA_SUCCESS) {
        return ret;
    }
    return CUDA_SUCCESS;
}

__attribute__((visibility("default")))
CUresult cuLaunchGrid(CUfunction f, int grid_width, int grid_height)
{
    CUresult ret, launch_ret;
    launch_ret = cu_launch_grid(f, grid_width, grid_height);
    if (launch_ret != CUDA_SUCCESS) {
        PRINT_ERROR("cu_launch_grid failed with %d\n", launch_ret);
        return launch_ret;
    }
    /*
     * XXX: Encryption routine of aes_ctr_dolbeau kernel itself calls cuLaunchGrid
     */
    if (f != aes_ctr_dolbeau) {
        /*
         * XXX: We wait until kernel is launched inside the function
         */
        ret = launch_encryption_overhead(f, grid_width, grid_height);
        if (ret == CUDA_ERROR_NOT_FOUND) {
            /*
             * Ignore not found as kernel may not have parameters to encrypt
             */
            return CUDA_SUCCESS;
        }
        if (ret != CUDA_SUCCESS) {
            PRINT_ERROR("launch_encryption_overhead failed with %d\n", ret);
            return ret;
        }
    }
    return CUDA_SUCCESS;
}
#endif