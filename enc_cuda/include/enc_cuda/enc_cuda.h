#pragma once

#include <cuda.h>

/* Override some of the functions in cuda.h to present encrypted versions:
 * 
 * CUresult cuMemAlloc(CUdeviceptr *dptr, unsigned int bytesize);
 * CUresult cuMemFree(CUdeviceptr dptr);
 * CUresult cuMemcpyDtoH(void *dstHost, CUdeviceptr srcDevice, unsigned int ByteCount);
 * CUresult cuMemcpyHtoD(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);
 * 
 * /!\ The CUdeviceptr type used by these functions is _not_ compatible with
 * the CUdeviceptr type used by regular CUDA functions! Internally, the
 * overiding functions use the CUdeviceptr type as a wrapper containing
 * additionnal metadata buffer, and a normale CUdeviceptr.
 * 
 */


/// @brief Setup CUDA for encrypted memcpys.
///        Must be called AFTER cuCtxCreate and BEFORE any cuMemAlloc.
///
/// @param key the 16 bytes symmetric key to use, transfered to the device. 
/// @param iv the initial counter value.
///
/// @return  CUDA_SUCCESS on success, or a CUDA error.
CUresult cuda_enc_setup(char * key, char * iv);
CUresult cuda_enc_release();
CUresult cuMemcpyHtoD(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);


// Expose the original functions

typedef CUresult cu_memalloc_func_t(CUdeviceptr *dptr, unsigned int bytesize);
typedef CUresult cu_memfree_func_t(CUdeviceptr dptr);
typedef CUresult cu_memcpy_d_to_h_func_t(void *dstHost, CUdeviceptr srcDevice, unsigned int ByteCount);
typedef CUresult cu_memcpy_h_to_d_func_t(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);
typedef CUresult cu_launch_grid_t(CUfunction f, int grid_width, int grid_height);
typedef CUresult cu_launch_grid_t(CUfunction f, int grid_width, int grid_height);
typedef CUresult cu_param_set_size_t(CUfunction hfunc, unsigned int numbytes);



extern cu_memalloc_func_t * cu_memalloc;
extern cu_memfree_func_t * cu_memfree;
extern cu_memcpy_d_to_h_func_t * cu_memcpy_dh;
extern cu_memcpy_h_to_d_func_t * cu_memcpy_hd;
extern cu_launch_grid_t * cu_launch_grid;
extern cu_param_set_size_t * cu_param_set_size;
