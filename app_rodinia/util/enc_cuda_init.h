#pragma once
#include <enc_cuda/enc_cuda.h>

#ifdef ENC_CUDA
#define ENC_CUDA_INIT                                                          \
  {                                                                            \
    char static_key[] = "0123456789abcdeF0123456789abcdeF";           \
    char static_iv[] = "12345678876543211234567887654321";            \
    CUresult ret = cuda_enc_setup(static_key, static_iv);                       \
    if (ret != CUDA_SUCCESS) {                                                 \
      fprintf(stderr, "cuda_enc_setup failed\n");                              \
      exit(1);                                                                 \
    }                                                                          \
  }
#else
#define ENC_CUDA_INIT
#endif
