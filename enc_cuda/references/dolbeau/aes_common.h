#ifndef _AES_COMMON_
#define _AES_COMMON_

#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

#include <stdio.h>

typedef void (*aes_encrypt_cuda_proto)(const uint32_t *,
                                       uint32_t *,
                                       const uint32_t *,
                                       const uint32_t ,
                                       const uint32_t* ,
                                       const uint32_t* ,
                                       const uint32_t* ,
                                       const uint32_t* ,
                                       const uint32_t* ,
                                       const uint32_t* );

static inline double wallclock(void) {
  struct timeval tv;
  struct timezone tz;
  double t;
  static double tr;
  
  gettimeofday(&tv, &tz);
  if (tr == 0.)
    tr = (double) tv.tv_sec;
    
  t = (double) tv.tv_sec - (double)tr;
  t += ((double) tv.tv_usec) / 1000000.0;
  
  return t;
}

#endif
