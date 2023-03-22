/*
Copyright (c) 2014, Romain Dolbeau, unless otherwise noted.
No claims is made upon work by others.

For the work by Romain Dolbeau:
All rights reserved

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

For the work by others:
See the indicated reference for the relevant license.
*/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


extern "C" {
unsigned int sleep(unsigned int seconds);
}
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/channels.h>

#include <openssl/evp.h>

#define SIZE ((1024*1024*128))

#include "aes_common.h"
static inline void print16c(const uint8_t* buf) {
  uint64_t i;
  for(i = 0 ; i < 16 ; i++) {
    printf("%02x ", buf[i]);
    if (i%4==3)
      printf(" ");
  }
  printf("\n");
}
#define CHECK(K)                                                        \
  do {                                                                  \
    err = K;                                                            \
    if (err) {                                                          \
      fprintf(stderr, "Oups, "#K" failed with %d (%s)\n", err, cudaGetErrorString(err)); \
      fflush(stderr);                                                   \
      exit(-2);                                                         \
    } } while (0)



texture<unsigned short, 1, cudaReadModeElementType> tFSbSq;

#include "aes_scalar.h"
#include "aes_gcm.h"
#define GPU_CREATE_ALL
#include "aes_gpu.h"


static inline void test_cuda_gcm(const uint8_t *in, uint8_t *out3, const uint8_t* out2, const uint32_t *aes_edrk,
                   const uint32_t *FT0, const uint32_t *FT1, const uint32_t *FT2, const uint32_t *FT3,
                   const uint32_t* IV,
                   aes_encrypt_cuda_proto fct, const int tbp) {
  uint64_t i, j;
  double t_[12], t0, t1;
  int count;
  int tc = 0;
  dim3 g, b;
  uint32_t *gin, *gout;
  uint32_t *gFT0 = NULL, *gFT1 = NULL, *gFT2 = NULL, *gFT3 = NULL;
  uint32_t *gFSb;
  uint32_t *gaes_edrk;
  uint32_t *gIV = NULL;
  uint32_t n_aes_block = (SIZE+15)/16;
  cudaError_t err;
  uint8_t accum[16];
  uint32_t temp[4];
  uint8_t H[16];
  uint8_t T[16];
  
  t_[tc++] = wallclock();
  CHECK(cudaMalloc((void**)&gin,(size_t)SIZE));
  CHECK(cudaMalloc((void**)&gout,(size_t)SIZE));
  if (FT0 != NULL)
    CHECK(cudaMalloc((void**)&gFT0,(size_t)1024));
  if (FT1 != NULL)
    CHECK(cudaMalloc((void**)&gFT1,(size_t)1024));
  if (FT2 != NULL)
    CHECK(cudaMalloc((void**)&gFT2,(size_t)1024));
  if (FT3 != NULL)
    CHECK(cudaMalloc((void**)&gFT3,(size_t)1024));
  CHECK(cudaMalloc((void**)&gFSb,(size_t)1024));
  CHECK(cudaMalloc((void**)&gaes_edrk,(size_t)256));
  if (IV != NULL)
    CHECK(cudaMalloc((void**)&gIV,(size_t)16));
  t_[tc++] = wallclock();
  CHECK(cudaMemcpy(gin, in, SIZE, cudaMemcpyHostToDevice));
  if (FT0 != NULL)
    CHECK(cudaMemcpy(gFT0, FT0, 1024, cudaMemcpyHostToDevice));
  if (FT1 != NULL)
    CHECK(cudaMemcpy(gFT1, FT1, 1024, cudaMemcpyHostToDevice));
  if (FT2 != NULL)
    CHECK(cudaMemcpy(gFT2, FT2, 1024, cudaMemcpyHostToDevice));
  if (FT3 != NULL)
    CHECK(cudaMemcpy(gFT3, FT3, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gFSb, FSb, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gaes_edrk, aes_edrk, 256, cudaMemcpyHostToDevice));
  if (IV != NULL)
    CHECK(cudaMemcpy(gIV, IV, 12, cudaMemcpyHostToDevice));
  if (IV != NULL)
    CHECK(cudaMemset(gIV+3,0,(size_t)4));
  CHECK(cudaMemset(gout,0,(size_t)SIZE));
  t_[tc++] = wallclock();
  g.y = g.z = 1;
  g.x = (n_aes_block+255)/256;
  g.x *= tbp;
  while (g.x >= 65536) {
    g.x /= 2;
    g.y *= 2;
    while ((g.x*g.y)<((n_aes_block+255)/256)*tbp)
      g.x++;
  }
  b.y = b.z = 1;
  b.x = 256;
  printf("%d/%d,%d\n", g.x,g.y,b.x);
  t_[tc++] = wallclock();
  /* start the AES-in-nearly-CTR mode straight away */
  fct<<<g,b>>>(gin,gout,gaes_edrk,n_aes_block, gFT0, gFT1, gFT2, gFT3, gFSb, gIV);
  {
    t_[tc++] = wallclock();
    memset(temp,0,16);
    aes_encrypt(temp,(uint32_t*)H,aes_edrk);
    memcpy(temp, IV, 12);
    ((unsigned char*)temp)[15] = 1;
    aes_encrypt(temp,(uint32_t*)T,aes_edrk);
    t_[tc++] = wallclock();
  }
  CHECK(cudaDeviceSynchronize());
  t_[tc++] = wallclock();
  CHECK(cudaMemcpy(out3,gout,SIZE,cudaMemcpyDeviceToHost)); 
  t_[tc++] = wallclock();
  {
    memset(accum,0,16);
    for (i = 0 ; i < SIZE ; i+=16) {
      addmul(accum,out3+i,16,H);
    }
    t_[tc++] = wallclock();
    unsigned char fb[16];
    memset(fb,0,16);
    (*(unsigned long long*)&fb[0]) = _bswap64((unsigned long long)(8*0));
    (*(unsigned long long*)&fb[8]) = _bswap64((unsigned long long)(8*SIZE));
    addmul(accum,fb,16,H);
    for (i = 0;i < 16;++i)
      (out3+SIZE)[i] = T[i] ^ accum[i];
    t_[tc++] = wallclock();
  }
  CHECK(cudaFree(gin));
  CHECK(cudaFree(gout));
  if (FT0 != NULL)
    CHECK(cudaFree(gFT0));
  if (FT1 != NULL)
    CHECK(cudaFree(gFT1));
  if (FT2 != NULL)
    CHECK(cudaFree(gFT2));
  if (FT3 != NULL)
    CHECK(cudaFree(gFT3));
  CHECK(cudaFree(gFSb));
  CHECK(cudaFree(gaes_edrk));
  if (IV != NULL)
    CHECK(cudaFree(gIV));
  t_[tc++] = wallclock();
  count = 0;
  for (i = 0 ; i < SIZE+16 && count<10 ; i++) {
    if (out2[i] != out3[i]) {
      fprintf(stderr, "out2[%" PRIu64 "] != out3[%" PRIu64 "] : %02x != %02x\n", i, i, out2[i], out3[i]);
      count++;
    }
  }
  if (count)
    exit(-1);
  printf("Total = %lf\n", t_[tc-1]-t_[0]);
  for (int k = 1 ; k < tc ; k++) {
    printf("  t_[%d] - t_[%d] = %lf\n", k, k-1, t_[k]-t_[k-1]);
  }
  // 6 was the compute call
  t1 = t_[6];
  t0 = t_[4];
  printf("%lf AES: Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
  // 9 was the compute call
  t1 = t_[9];
  t0 = t_[7];
  printf("%lf GCM Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
  t1 = t_[tc-2];
  t0 = t_[1];
  printf("%lf NOMALLOCFREE Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
  t1 = t_[tc-1];
  t0 = t_[0];
  printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
    
}

void test_cuda_cpy(const uint8_t *in, uint8_t *out3, const uint8_t* out2, const uint32_t *aes_edrk,
               const uint32_t *FT0, const uint32_t *FT1, const uint32_t *FT2, const uint32_t *FT3,
               const uint32_t* IV, const uint16_t* FSbSq,
               aes_encrypt_cuda_proto fct, const int tbp) {
  uint64_t i, j;
  double t_[10], t0, t1;
  int count;
    int tc = 0;
    dim3 g, b;
    uint32_t *gin, *gout;
    uint32_t *gFT0 = NULL, *gFT1 = NULL, *gFT2 = NULL, *gFT3 = NULL;
    uint32_t *gFSb;
    uint32_t *gaes_edrk;
    uint32_t *gIV = NULL;
    uint16_t * gFSbSq;
    uint32_t n_aes_block = (SIZE+15)/16;
    cudaError_t err;
    cudaArray *FSbSqArray;
    cudaChannelFormatDesc channelDesc =
      cudaCreateChannelDesc(16, 0, 0, 0, cudaChannelFormatKindUnsigned);

    t_[tc++] = wallclock();
    CHECK(cudaMalloc((void**)&gin,(size_t)SIZE));
    CHECK(cudaMalloc((void**)&gout,(size_t)SIZE));
    if (FT0 != NULL)
      CHECK(cudaMalloc((void**)&gFT0,(size_t)1024));
    if (FT1 != NULL)
      CHECK(cudaMalloc((void**)&gFT1,(size_t)1024));
    if (FT2 != NULL)
      CHECK(cudaMalloc((void**)&gFT2,(size_t)1024));
    if (FT3 != NULL)
      CHECK(cudaMalloc((void**)&gFT3,(size_t)1024));
    CHECK(cudaMalloc((void**)&gFSb,(size_t)1024));
    CHECK(cudaMalloc((void**)&gaes_edrk,(size_t)256));
    if (IV != NULL)
      CHECK(cudaMalloc((void**)&gIV,(size_t)16));
    t_[tc++] = wallclock();
    if (FSbSq != NULL) {
//       CHECK(cudaMallocArray(&FSbSqArray,&channelDesc,65536,0,cudaArrayDefault));
      CHECK(cudaMalloc(&gFSbSq,131072));
    }
    CHECK(cudaMemcpy(gin, in, SIZE, cudaMemcpyHostToDevice));
    if (FT0 != NULL)
      CHECK(cudaMemcpy(gFT0, FT0, 1024, cudaMemcpyHostToDevice));
    if (FT1 != NULL)
      CHECK(cudaMemcpy(gFT1, FT1, 1024, cudaMemcpyHostToDevice));
    if (FT2 != NULL)
      CHECK(cudaMemcpy(gFT2, FT2, 1024, cudaMemcpyHostToDevice));
    if (FT3 != NULL)
      CHECK(cudaMemcpy(gFT3, FT3, 1024, cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(gFSb, FSb, 1024, cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(gaes_edrk, aes_edrk, 256, cudaMemcpyHostToDevice));
    if (IV != NULL)
      CHECK(cudaMemcpy(gIV, IV, 16, cudaMemcpyHostToDevice));
    if (FSbSq != NULL) {
//       CHECK(cudaMemcpyToArray(FSbSqArray,
//                               0,
//                               0,
//                               FSbSq,
//                               131072,
//                               cudaMemcpyHostToDevice));
//       tFSbSq.addressMode[0] = cudaAddressModeWrap;
//       tFSbSq.filterMode = cudaFilterModePoint;
//       tFSbSq.normalized = false;
//       CHECK(cudaBindTextureToArray(tFSbSq, FSbSqArray, channelDesc));
      CHECK(cudaMemcpy(gFSbSq,FSbSq,131072,cudaMemcpyHostToDevice));
      CHECK(cudaBindTexture(NULL,tFSbSq,gFSbSq,channelDesc,131072));
    }
    CHECK(cudaMemset(gout,0,(size_t)SIZE));
    t_[tc++] = wallclock();
    g.y = g.z = 1;
    g.x = (n_aes_block+255)/256;
    g.x *= tbp;
    while (g.x >= 65536) {
      g.x /= 2;
      g.y *= 2;
      while ((g.x*g.y)<((n_aes_block+255)/256)*tbp)
        g.x++;
    }
    b.y = b.z = 1;
    b.x = 256;
//     printf("%d/%d,%d\n", g.x,g.y,b.x);
    t_[tc++] = wallclock();
    fct<<<g,b>>>(gin,gout,gaes_edrk,n_aes_block, gFT0, gFT1, gFT2, gFT3, gFSb, gIV);
    CHECK(cudaDeviceSynchronize());
    t_[tc++] = wallclock();
    CHECK(cudaMemcpy(out3,gout,SIZE,cudaMemcpyDeviceToHost)); 
    t_[tc++] = wallclock();
    CHECK(cudaFree(gin));
    CHECK(cudaFree(gout));
    if (FT0 != NULL)
      CHECK(cudaFree(gFT0));
    if (FT1 != NULL)
      CHECK(cudaFree(gFT1));
    if (FT2 != NULL)
      CHECK(cudaFree(gFT2));
    if (FT3 != NULL)
      CHECK(cudaFree(gFT3));
    CHECK(cudaFree(gFSb));
    CHECK(cudaFree(gaes_edrk));
    if (IV != NULL)
      CHECK(cudaFree(gIV));
    if (FSbSq != NULL) {
//       CHECK(cudaUnbindTexture(tFSbSq));
//       CHECK(cudaFreeArray(FSbSqArray));
      CHECK(cudaFree(gFSbSq));
    }
    t_[tc++] = wallclock();
    count = 0;
    for (i = 0 ; i < SIZE && count<10 ; i++) {
      if (out2[i] != out3[i]) {
        fprintf(stderr, "out2[%" PRIu64 "] != out3[%" PRIu64 "] : %02x != %02x\n", i, i, out2[i], out3[i]);
        count++;
      }
    }
    if (count)
      exit(-1);
    printf("Total = %lf\n", t_[tc-1]-t_[0]);
    for (int k = 1 ; k < tc ; k++) {
      printf("  t_[%d] - t_[%d] = %lf\n", k, k-1, t_[k]-t_[k-1]);
    }
    // 4 was the compute call
    t1 = t_[4];
    t0 = t_[3];
    fflush(stderr);
    printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
sleep(1);
}



void test_cuda_nocpy(const uint8_t *in, uint8_t *out3, const uint8_t* out2, const uint32_t *aes_edrk,
               const uint32_t *FT0, const uint32_t *FT1, const uint32_t *FT2, const uint32_t *FT3,
               const uint32_t* IV, const uint16_t* FSbSq,
               aes_encrypt_cuda_proto fct, const int tbp) {
  uint64_t i, j;
  double t_[10], t0, t1;
  int count;
    int tc = 0;
    dim3 g, b;
    uint32_t *gin, *gout;
    uint32_t *gFT0 = NULL, *gFT1 = NULL, *gFT2 = NULL, *gFT3 = NULL;
    uint32_t *gFSb;
    uint32_t *gaes_edrk;
    uint32_t *gIV = NULL;
    uint16_t * gFSbSq;
    uint32_t n_aes_block = (SIZE+15)/16;
    cudaError_t err;
    cudaChannelFormatDesc channelDesc =
      cudaCreateChannelDesc(16, 0, 0, 0, cudaChannelFormatKindUnsigned);

    t_[tc++] = wallclock();
    CHECK(cudaHostGetDevicePointer((void**)&gin,(void*)in,0));
    CHECK(cudaHostGetDevicePointer((void**)&gout,(void*)out3,0));
    if (FT0 != NULL)
      CHECK(cudaHostGetDevicePointer((void**)&gFT0,(void*)FT0,0));
    if (FT1 != NULL)
      CHECK(cudaHostGetDevicePointer((void**)&gFT1,(void*)FT1,0));
    if (FT2 != NULL)
      CHECK(cudaHostGetDevicePointer((void**)&gFT2,(void*)FT2,0));
    if (FT3 != NULL)
      CHECK(cudaHostGetDevicePointer((void**)&gFT3,(void*)FT3,0));
    CHECK(cudaHostGetDevicePointer((void**)&gFSb,(void*)FSb,0));
    CHECK(cudaHostGetDevicePointer((void**)&gaes_edrk,(void*)aes_edrk,0));
    if (IV != NULL)
      CHECK(cudaHostGetDevicePointer((void**)&gIV,(void*)IV,0));
    t_[tc++] = wallclock();
    if (FSbSq != NULL) {
      fprintf(stderr, "FSbSq != NULL && nocpy incompatible\n");
      return;
    }
//     CHECK(cudaMemset(gout,0,(size_t)SIZE));
    t_[tc++] = wallclock();
    g.y = g.z = 1;
    g.x = (n_aes_block+255)/256;
    g.x *= tbp;
    while (g.x >= 65536) {
      g.x /= 2;
      g.y *= 2;
      while ((g.x*g.y)<((n_aes_block+255)/256)*tbp)
        g.x++;
    }
    b.y = b.z = 1;
    b.x = 256;
//     printf("%d/%d,%d\n", g.x,g.y,b.x);
    t_[tc++] = wallclock();
    fct<<<g,b>>>(gin,gout,gaes_edrk,n_aes_block, gFT0, gFT1, gFT2, gFT3, gFSb, gIV);
    CHECK(cudaDeviceSynchronize());
    t_[tc++] = wallclock();
    t_[tc++] = wallclock();
    t_[tc++] = wallclock();
    count = 0;
    for (i = 0 ; i < SIZE && count<10 ; i++) {
      if (out2[i] != out3[i]) {
        fprintf(stderr, "out2[%" PRIu64 "] != out3[%" PRIu64 "] : %02x != %02x\n", i, i, out2[i], out3[i]);
        count++;
      }
    }
    if (count)
      exit(-1);
    printf("Total = %lf\n", t_[tc-1]-t_[0]);
    for (int k = 1 ; k < tc ; k++) {
      printf("  t_[%d] - t_[%d] = %lf\n", k, k-1, t_[k]-t_[k-1]);
    }
    // 4 was the compute call
    t1 = t_[4];
    t0 = t_[3];
    fflush(stderr);
    printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
sleep(1); 
}


#ifdef NOCOPY
#define test_cuda test_cuda_nocpy
uint32_t* FT0;
uint32_t* FT1;
uint32_t* FT2;
uint32_t* FT3;
uint32_t* FSb;
#else
#define test_cuda test_cuda_cpy
#endif


int main(int argc, char **argv) {
  uint32_t keyr[8] = {0xc47b0294, 0xdbbbee0f, 0xec4757f2, 0x2ffeee35, 0x87ca4730, 0xc3d33b69, 0x1df38bab, 0x076bc558 };/* 46f2fb34 2d6f0ab4 77476fc50 1242c5f on 0[128] */
  uint32_t key[8];
  uint64_t i, j;
  double t0, t1;
  int count;
  cudaError_t err;
  uint16_t FSbSq[65536];
  uint8_t *out1 = new uint8_t[SIZE+16]; /* +16 -> AES-GCM tag */
  uint8_t *out2 = new uint8_t[SIZE+16];

#ifdef NOCOPY
  uint8_t *in;
  uint8_t *out3;
  uint32_t *IV;
  uint32_t *aes_edrk;
  uint32_t *aes_edrk_diag;

  CHECK(cudaSetDeviceFlags(cudaDeviceMapHost));

  CHECK(cudaHostAlloc(&in,SIZE,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&out3,SIZE+16,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&IV,16,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&aes_edrk,256,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&aes_edrk_diag,256,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&FT0,1024,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&FT1,1024,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&FT2,1024,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&FT3,1024,cudaHostAllocMapped));
  CHECK(cudaHostAlloc(&FSb,1024,cudaHostAllocMapped));
  memcpy(FT0,FT0_,1024);
  memcpy(FT1,FT1_,1024);
  memcpy(FT2,FT2_,1024);
  memcpy(FT3,FT3_,1024);
  memcpy(FSb,FSb_,1024);
#else
  uint8_t *in = new uint8_t[SIZE];
  uint8_t *out3 = new uint8_t[SIZE+16];
  uint32_t IV[4];
  uint32_t aes_edrk[64];
  uint32_t aes_edrk_diag[64];
#endif

#if 0 //def NOCOPY
  CHECK(cudaHostRegister(in,SIZE,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(out3,SIZE+16,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(IV,16,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(aes_edrk,256,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(aes_edrk_diag,256,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(FT0,1024,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(FT1,1024,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(FT2,1024,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(FT3,1024,cudaHostRegisterMapped));
  CHECK(cudaHostRegister(FSb,1024,cudaHostRegisterMapped));
#endif
  
  for (i = 0 ; i < 256 ; i++) {
    for (j = 0 ; j < 256 ; j++) {
      FSbSq[j+i*256] = FSb[j] | (FSb[i]<<8);
    }
  }
  
  for (i = 0 ; i < 64 ; i++)
    aes_edrk[i] = 0;

  srandom(0); // reproducible

  for (i = 0 ; i < 4 ; i++)
    IV[i] = random();

  for (i = 0 ; i < SIZE/4 ; i++)
    ((uint32_t*)in)[i] = random();
  
  for (i = 0 ; i < SIZE ; i++)
    out1[i] = out2[i] = out3[i] = 0;

  for (i = 0 ; i < 8 ; i++) {
    key[i] = __builtin_bswap32(keyr[i]);
  }
  aes_set_key(key, aes_edrk);
  /* ** diagonalization of subkeys */
  /* first four are not diagonalized */
  for (i = 0 ; i < 4 ; i++) {
    aes_edrk_diag[i] = aes_edrk[i];
  }
  /* then all but last four are */
  for (i = 4 ; i < 56 ; i+= 4) {
    diag1cpu(aes_edrk_diag+i, aes_edrk+i);
  }
  /* last four */
  for (i = 56 ; i < 64 ; i++) {
    aes_edrk_diag[i] = aes_edrk[i];
  }
  
#define TEST_CUDA(K,FT0,FT1,FT2,FT3,IV,FSQ,FN,TBP)      \
  printf("Testing "#FN" ...\n");fflush(stdout);         \
  test_cuda(in, out3, out2, K,                          \
            FT0, FT1, FT2, FT3, IV,FSQ,                 \
            &FN, TBP); fflush(stderr);fflush(stdout);
  
#ifdef TEST_ECB
#if 0
  t0 = wallclock();
  for (i = 0 ; i < SIZE ; i+= 16) {
    aes_encrypt((uint32_t*)(in+i), (uint32_t*)(out1+i), aes_edrk);
  }
  t1 = wallclock();
  printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
//   for (i = 0 ; i < SIZE ; i+= 16) {
//     print16c((out1+i));
//   }


  for (i = 0 ; i < SIZE ; i+= 16) {
    aes_decrypt((uint32_t*)(out1+i), (uint32_t*)(in+i), aes_edrk);
  }
  count=0;
  for (i = 0 ; i < SIZE && count<10 ; i++) {
    if (in[i] != (i&0xFF)) {
      fprintf(stderr, "in[%" PRIu64 "] = 0x%02x != 0x%02x\n", i, in[i], i&0xFF);
      count++;
    }
  }
  if (count)
    exit(-1);
#endif

  {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e((unsigned char*)key, 32);
    t0 = wallclock();
    e.ProcessData((unsigned char*)out2, (unsigned char*)in, SIZE);
    t1 = wallclock();
    printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
    //   for (i = 0 ; i < SIZE ; i+= 16) {
    //     print16c((out2+i));
    //   }
  }

#if 0
  count = 0;
  for (i = 0 ; i < SIZE && count<10 ; i++) {
    if (out1[i] != out2[i]) {
      fprintf(stderr, "out1[%" PRIu64 "] != out2[%" PRIu64 "] : %02x != %02x\n", i, i, out1[i], out2[i]);
      count++;
    }
  }
  if (count)
    exit(-1);
#endif

/* start things */
  TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, NULL, NULL, aes_encrypt_cuda_FT_SEQ1_PRMT_32nocoalnocoal, 1);

#include "aes_cuda_ecb.h"

  TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, NULL, NULL, aes_encrypt_cuda_half, 2);
  TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, NULL, NULL, aes_encrypt_cuda_quarter, 4);
#endif

#ifdef TEST_CTR
  {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption s;
    s.SetKeyWithIV((unsigned char*)key, 32, (unsigned char*)IV);
    t0 = wallclock();
    s.ProcessString((unsigned char*)out2, (unsigned char*)in, SIZE);
    t1 = wallclock();
    printf("%lf Mbytes/seconds (%lf in %lf)\n", ((double)SIZE/(t1-t0))/1000000., (double)SIZE/1000000., t1-t0);
  }


/* start things */
  TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, IV, NULL, aes_ctr_cuda_FT_SEQ1_PRMT_32nocoalnocoal, 1);

  #include "aes_cuda_ctr.h"

//   TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, IV, NULL, aes_ctr_cuda_half, 2);
//   TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, IV, NULL, aes_ctr_cuda_quarter, 4);
#endif

#ifdef TEST_GCM
  try {
    double t2;
    std::string cipher;
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((unsigned char*)key, 32, (unsigned char*)IV, 12);
    CryptoPP::AuthenticatedEncryptionFilter aef(e, new CryptoPP::StringSink( cipher ), false, 16);
//     aef.ChannelPut(CryptoPP::AAD_CHANNEL, ad, adlen);
//     aef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    t0 = wallclock();
//     aef.ChannelPut(CryptoPP::AAD_CHANNEL, (byte*)NULL, (size_t)0);
//     aef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    aef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, in, SIZE);
    aef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    t1 = wallclock();
    memcpy(out2, cipher.c_str(), SIZE+16);
    t2 = wallclock();
    printf("%lf Mbytes/seconds (%lf in %lf) [%lf for %lf]\n",
           ((double)SIZE/(t1-t0))/1000000.,
           (double)SIZE/1000000., t1-t0,
           ((double)SIZE/(t2-t0))/1000000., t2-t0);
  } catch (CryptoPP::Exception& e ) {
    fprintf(stderr, "Oups, Crypto++ AES-GCM failed");
  }
  { 
    EVP_CIPHER_CTX x;
    int outlen = 0;
    int ok = 1;
    
    t0 = wallclock();
    EVP_CIPHER_CTX_init(&x);
    if (ok == 1) ok = EVP_EncryptInit_ex(&x,EVP_aes_256_gcm(),0,0,0);
    if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_SET_IVLEN,12,0);
    if (ok == 1) ok = EVP_EncryptInit_ex(&x,0,0,(const unsigned char *)key,(const unsigned char *)IV);
//     if (ok == 1) ok = EVP_EncryptUpdate(&x,0,&outlen,ad,adlen);
    if (ok == 1) ok = EVP_EncryptUpdate(&x,out3,&outlen,in,SIZE);
    if (ok == 1) ok = EVP_EncryptFinal_ex(&x,out3,&outlen);
    if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_GET_TAG,16,out3 + SIZE);
    EVP_CIPHER_CTX_cleanup(&x);
    t1 = wallclock();
    if (ok != 1)
      fprintf(stderr, "Oups, openssl AES-GCM failed");
    count = 0;
    for (i = 0 ; i < SIZE+16 && count<10 ; i++) {
      if (out2[i] != out3[i]) {
        fprintf(stderr, "out2[%" PRIu64 "] != out3[%" PRIu64 "] : %02x != %02x\n", i, i, out2[i], out3[i]);
        count++;
      }
    }
    if (count)
      exit(-1);
    printf("%lf Mbytes/seconds (%lf in %lf)\n",
           ((double)SIZE/(t1-t0))/1000000.,
           (double)SIZE/1000000., t1-t0);
  }
  {
    printf("Testing  aes_gcm_cuda_BTB320_PRMT_8nocoalnocoal ...\n");
    fflush(stdout);
    test_cuda_gcm(in, out3, out2, aes_edrk,
                  FT0, NULL, NULL, NULL,
                  IV, /* NULL, */
                  &aes_gcm_cuda_BTB320_PRMT_8nocoalnocoal, 1);
  }
#endif


#if 0 //def NOCOPY
  CHECK(cudaHostUnregister(in));
  CHECK(cudaHostUnregister(out3));
  CHECK(cudaHostUnregister(IV));
  CHECK(cudaHostUnregister(aes_edrk));
  CHECK(cudaHostUnregister(aes_edrk_diag));
  CHECK(cudaHostUnregister(FT0));
  CHECK(cudaHostUnregister(FT1));
  CHECK(cudaHostUnregister(FT2));
  CHECK(cudaHostUnregister(FT3));
  CHECK(cudaHostUnregister(FSb));
#endif

#ifdef NOCOPY
  CHECK(cudaFreeHost(in));
  CHECK(cudaFreeHost(out3));
  CHECK(cudaFreeHost(IV));
  CHECK(cudaFreeHost(aes_edrk));
  CHECK(cudaFreeHost(aes_edrk_diag));
  CHECK(cudaFreeHost(FT0));
  CHECK(cudaFreeHost(FT1));
  CHECK(cudaFreeHost(FT2));
  CHECK(cudaFreeHost(FT3));
  CHECK(cudaFreeHost(FSb));
#else  
  delete(in);
  delete(out3);
#endif
  delete(out1);
  delete(out2);

  return 0;
}
