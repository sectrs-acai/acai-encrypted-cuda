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
#include <cstdio>
#include <cstdlib>
#if __cplusplus >= 201103L
#include <cstdint>
#else
#define uint64_t unsigned long long
#define uint32_t unsigned int
#define uint16_t unsigned short
#define uint8_t unsigned char
#endif

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/channels.h>

#include <openssl/evp.h>

#include "aes_common.h"
#include "aes_scalar.h"
#include "aes_gcm.h"

texture<unsigned short, 1, cudaReadModeElementType> tFSbSq;

#include "aes_gpu.h"
#include "gpu_aes_gcm.h"

/* AES256GCM encryption.
   this is from the supercop benchmark <http://bench.cr.yp.to/supercop.html>
   directory "supercop-$VERSION/crypto_aead/aes256gcmv1/openssl"
*/
int crypto_aead_encrypt_openssl(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  EVP_CIPHER_CTX x;
  int outlen = 0;
  int ok = 1;

  if (adlen > 536870912) return -111;
  /* OpenSSL needs to put lengths into an int */
  if (mlen > 536870912) return -111;

  EVP_CIPHER_CTX_init(&x);
  if (ok == 1) ok = EVP_EncryptInit_ex(&x,EVP_aes_256_gcm(),0,0,0);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_SET_IVLEN,12,0);
  if (ok == 1) ok = EVP_EncryptInit_ex(&x,0,0,k,npub);
  if (ok == 1) ok = EVP_EncryptUpdate(&x,0,&outlen,ad,adlen);
  if (ok == 1) ok = EVP_EncryptUpdate(&x,c,&outlen,m,mlen);
  if (ok == 1) ok = EVP_EncryptFinal_ex(&x,c,&outlen);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_GET_TAG,16,c + mlen);
  EVP_CIPHER_CTX_cleanup(&x);

  if (ok == 1) {
    *clen = mlen + 16;
    return 0;
  }
  return -111;
}

/* AES256GCM decryption.
   this is from the supercop benchmark <http://bench.cr.yp.to/supercop.html>
   directory "supercop-$VERSION/crypto_aead/aes256gcmv1/openssl"
*/
int crypto_aead_decrypt_openssl(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  EVP_CIPHER_CTX x;
  int outlen = 0;
  int ok = 1;
  
  if (adlen > 536870912) return -111; 
  /* OpenSSL needs to put lengths into an int */
  if (clen > 536870912) return -111;

  if (clen < 16) return -1;
  clen -= 16;

  EVP_CIPHER_CTX_init(&x);
  if (ok == 1) ok = EVP_DecryptInit_ex(&x,EVP_aes_256_gcm(),0,0,0);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_SET_IVLEN,12,0);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(&x,EVP_CTRL_GCM_SET_TAG,16,(unsigned char *) c + clen);
  if (ok == 1) ok = EVP_DecryptInit_ex(&x,0,0,k,npub);
  if (ok == 1) ok = EVP_DecryptUpdate(&x,0,&outlen,ad,adlen);
  if (ok == 1) ok = EVP_DecryptUpdate(&x,m,&outlen,c,clen);
  if (ok == 1) ok = EVP_DecryptFinal_ex(&x,m + clen,&outlen);
  EVP_CIPHER_CTX_cleanup(&x);

  if (ok == 1) {
    *mlen = clen;
    return 0;
  }
  return -1; /* forgery; XXX: or out of memory? hmmm */
}

/* AES256GCM encryption.
   this is from the supercop benchmark <http://bench.cr.yp.to/supercop.html>
   directory "supercop-$VERSION/crypto_aead/aes256gcmv1/cryptopp"
*/
int crypto_aead_encrypt_cryptopp(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  try {
    std::string cipher;
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(k, 32, npub, 12);
    CryptoPP::AuthenticatedEncryptionFilter aef(e, new CryptoPP::StringSink( cipher ), false, 16);
    aef.ChannelPut(CryptoPP::AAD_CHANNEL, ad, adlen);
    aef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    aef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, m, mlen);
    aef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    
    *clen = mlen + 16;
    
    memcpy(c, cipher.c_str(), *clen);
    
    return 0;
  } catch (CryptoPP::Exception& e ) {
    return -111;
  }
}

/* AES256GCM decryption.
   this is from the supercop benchmark <http://bench.cr.yp.to/supercop.html>
   directory "supercop-$VERSION/crypto_aead/aes256gcmv1/cryptopp"
*/
int crypto_aead_decrypt_cryptopp(
  unsigned char *m,unsigned long long *outputmlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  try {
    std::string plain;
    CryptoPP::GCM<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(k, 32, npub, 12);
    CryptoPP::AuthenticatedDecryptionFilter adf( d, NULL, CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16 );
    *outputmlen = clen-16;
    adf.ChannelPut(CryptoPP::DEFAULT_CHANNEL, c+clen-16, 16);
    adf.ChannelPut(CryptoPP::AAD_CHANNEL, ad, adlen); 
    adf.ChannelPut(CryptoPP::DEFAULT_CHANNEL, c, clen-16);
    adf.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    adf.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    if (!adf.GetLastResult())
      return -111;
    adf.SetRetrievalChannel(CryptoPP::DEFAULT_CHANNEL);
    adf.Get(m, *outputmlen);
    return 0;
  } catch (CryptoPP::Exception& e ) {
    return -111;
  }
}

#define CHECK(K)                                                        \
  do {                                                                  \
    err = K;                                                            \
    if (err) {                                                          \
      fprintf(stderr, "Oups, "#K" failed with %d (%s)\n", err, cudaGetErrorString(err)); \
      fflush(stderr);                                                   \
      exit(-2);                                                         \
    } } while (0)
#define CHECKRETRY46(K)                                                 \
  do {                                                                  \
    int tcount = 0;                                                     \
    do { err = K; tcount++; } while (err == 46 && tcount < 3);          \
    if (err) {                                                          \
      fprintf(stderr, "Oups, "#K" failed with %d (%s)\n", err, cudaGetErrorString(err)); \
      fflush(stderr);                                                   \
      exit(-2);                                                         \
    } } while (0)

/* gpu pointers */
uint32_t *gin, *gout;
uint32_t *gFT0, *gFT1, *gFT2, *gFT3;
uint32_t *gFSb;
uint32_t *gaes_edrk;
uint32_t *gIV;
cudaStream_t streams[2];

static inline void print16c(const uint8_t* buf) {
  uint64_t i;
  for(i = 0 ; i < 16 ; i++) {
    printf("%02x ", buf[i]);
    if (i%4==3)
      printf(" ");
  }
  printf("\n");
}

#ifndef GCM_CUDA_CHUNK_SIZE
#define GCM_CUDA_CHUNK_SIZE (2*1024*1024) /* must be a multiple of 4096 */
#endif
#ifndef GCM_CUDA_CHUNK_NUMBLOCK
#define GCM_CUDA_CHUNK_NUMBLOCK 8
#endif
//#define GCM_CUDA_ENCRYPT_BY_CHUNK /* whether we want to encrypt by chunk, i.e., overlap AES & GCM during encryption */
//#define GCM_CUDA_ENCRYPT_BY_CHUNK_FIXED_CHUNK /* whether the crypt size is fixed, and not size/GCM_CUDA_CHUNK_NUMBLOCK */
//#define GPU_NOXOR /* if defined, GPU doesn't do XOR - the CPU does */

/* initialization for the CUDA stuff.
   allocates GPU-side buffers, streams, ...
   can also set the cache config or pick
   a GPU.
   THE HYBRID CODE IS NOT REENTRANT !
   Don't use in more than one thread.
*/
static size_t gcm_cuda_max_size;
static int gcm_cuda_max_blocks;
void init_crypto_aead_cuda(const size_t SIZE, const int maxb) {
  cudaError_t err;
  gcm_cuda_max_size = SIZE;
  gcm_cuda_max_blocks = maxb;
  CHECKRETRY46(cudaSetDeviceFlags(cudaDeviceScheduleYield));
  CHECKRETRY46(cudaMalloc((void**)&gin,SIZE));
  CHECK(cudaMalloc((void**)&gout,SIZE));
  CHECK(cudaMalloc((void**)&gFT0,(size_t)1024));
  CHECK(cudaMalloc((void**)&gFT1,(size_t)1024));
  CHECK(cudaMalloc((void**)&gFT2,(size_t)1024));
  CHECK(cudaMalloc((void**)&gFT3,(size_t)1024));
  CHECK(cudaMalloc((void**)&gFSb,(size_t)1024));
  CHECK(cudaMalloc((void**)&gaes_edrk,(size_t)256));
  CHECK(cudaMalloc((void**)&gIV,(size_t)16*maxb));
  CHECK(cudaMemcpy(gFT0, FT0, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gFT1, FT1, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gFT2, FT2, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gFT3, FT3, 1024, cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(gFSb, FSb, 1024, cudaMemcpyHostToDevice));
  int pmin, pmax;
  CHECK(cudaDeviceGetStreamPriorityRange(&pmin,&pmax));
  /* Beware: priority is not actually suported on Jetson TK1
     (pmin == pmax == 0), only on Tesla/Quadro CC3.5+
  */
  /* minimum priority stream : AES */
  CHECK(cudaStreamCreateWithPriority(&streams[0], cudaStreamDefault, pmin));
  /* maximum priority stream : recover data from partial AES for pipelining */
  CHECK(cudaStreamCreateWithPriority(&streams[1],cudaStreamDefault, pmax));
  /*
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB320_PRMT_8nocoalnocoal, cudaFuncCachePreferL1));
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB320_PRMT_8coalnocoal, cudaFuncCachePreferShared));
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB320_PRMT_8nocoalcoal, cudaFuncCachePreferShared));
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB320_PRMT_8coalcoal, cudaFuncCachePreferShared));
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB32DIAGKEY0_PRMT_8coalcoal, cudaFuncCachePreferL1));
  CHECK(cudaFuncSetCacheConfig(&aes_gcm_cuda_BTB32DIAGKEY0_PRMT_8nocoalnocoal, cudaFuncCachePreferL1));
  */
}

/* free the resources allocated by the init function */
void finish_crypto_aead_cuda(void) {
  cudaError_t err;
  CHECK(cudaFree(gin));
  CHECK(cudaFree(gout));
  CHECK(cudaFree(gFT0));
  CHECK(cudaFree(gFT1));
  CHECK(cudaFree(gFT2));
  CHECK(cudaFree(gFT3));
  CHECK(cudaFree(gFSb));
  CHECK(cudaFree(gaes_edrk));
  CHECK(cudaFree(gIV));
  CHECK(cudaStreamDestroy(streams[0]));
}

/* same interface as the supercop crypto_aead_encrypt()
   functions.
   *But* it requires initialization and clean-up
   */
int crypto_aead_encrypt_cuda(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned long long nfullgpuaesblock = mlen/(256*16);
  unsigned long long nfullaesblock;
  unsigned long long dataleft;
  uint32_t aes_edrk[64];
  uint32_t aes_edrk_diag[64];
  unsigned char accum[16], H[16], T[16], temp[16], fb[16];
  cudaError_t err;
  //aes_gcm_cuda_BTB320_PRMT_8nocoalnocoal
  //aes_gcm_cuda_BTB32DIAGKEY0_PRMT_8coalcoal
#ifdef GPU_NOXOR
  aes_encrypt_cuda_proto fct = &aes_gcmnoxor_cuda_BTB32DIAGKEY0_PRMT_8coalcoal;
#else
  aes_encrypt_cuda_proto fct = &aes_gcm_cuda_BTB32DIAGKEY0_PRMT_8coalcoal;
#endif
#ifdef GCM_CUDA_ENCRYPT_BY_CHUNK
  unsigned long long nchunk;
  size_t gcm_cuda_chunk_size = GCM_CUDA_CHUNK_SIZE;
#ifndef GCM_CUDA_ENCRYPT_BY_CHUNK_FIXED_CHUNK
  gcm_cuda_chunk_size = ((mlen/GCM_CUDA_CHUNK_NUMBLOCK)+4095) & ~4095;
  if (gcm_cuda_chunk_size < (512*1024))
    gcm_cuda_chunk_size = 512*1024;
  if (gcm_cuda_chunk_size > 16*1024*1024)
    gcm_cuda_chunk_size = 16*1024*1024;
  /* fixme: check with gcm_cuda_max_blocks */
#endif
#endif
  int i, j;
  dim3 g, b;
  aes_set_key((const unsigned int*)k, aes_edrk);
  {
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
  }
  *clen = mlen+16;
  if ((nfullgpuaesblock*256*16) > gcm_cuda_max_size) {
    nfullgpuaesblock = gcm_cuda_max_size/(256*16);
  }
  g.y = g.z = 1;
  g.x = nfullgpuaesblock;
  g.x *= 1; /* tbp */
  while (g.x >= 65536) {
    g.x /= 2;
    g.y *= 2;
  }
  nfullgpuaesblock = g.x*g.y/1; /* tbp */
  nfullaesblock = 256*nfullgpuaesblock;
#ifdef GCM_CUDA_ENCRYPT_BY_CHUNK
  nchunk = (nfullgpuaesblock+(gcm_cuda_chunk_size/4096)-1)/(gcm_cuda_chunk_size/4096);
  cudaEvent_t event[nchunk];
#endif
  dataleft = mlen-(nfullgpuaesblock*256*16);
  b.y = b.z = 1;
  b.x = 256;
  if (nfullgpuaesblock>0) {
    memset(temp,0,16);
    memcpy(temp,npub,12);
    /* Since we're in non-pinned memory, cudaMemcpyAsync probably won't help */
    //   CHECK(cudaMemcpyAsync(gaes_edrk,aes_edrk,256,cudaMemcpyHostToDevice,0));
    //   CHECK(cudaMemcpyAsync(gIV,npub,12,cudaMemcpyHostToDevice,0));
    //   CHECK(cudaMemcpyAsync(gin,m,nfullgpuaesblock*256*16,cudaMemcpyHostToDevice,0/*streams[0]*/));
    /* BEWARE which keys are send (diagonalized or not) */
    CHECK(cudaMemcpy(gaes_edrk,aes_edrk_diag,256,cudaMemcpyHostToDevice));
    //CHECK(cudaMemcpy(gaes_edrk,aes_edrk,256,cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(gIV,temp,16,cudaMemcpyHostToDevice));
#if !defined(GPU_NOXOR)
    CHECK(cudaMemcpy(gin,m,nfullgpuaesblock*256*16,cudaMemcpyHostToDevice));
#endif
#ifdef GCM_CUDA_ENCRYPT_BY_CHUNK
    if (nchunk > 1) {
      uint32_t bIV[(nchunk-1)*4];
      memset(bIV,0,(nchunk-1)*4*sizeof(uint32_t));
      for (i = 1 ; i < nchunk ; i++) {
        memcpy(bIV+(i-1)*4,npub,12);
        bIV[(4*i)-1] = __builtin_bswap32(i*gcm_cuda_chunk_size/16);
      }
      CHECK(cudaMemcpy(gIV+4,bIV,(nchunk-1)*4*sizeof(uint32_t),cudaMemcpyHostToDevice));
    }
    for (i = 0 ; i < nchunk ; i++) {
      CHECK(cudaEventCreate(event+i));
    }
    for (i = 0 ; i < nchunk ; i++) {
      unsigned long long naesb = gcm_cuda_chunk_size/16;
      if (naesb > (nfullaesblock-(i*gcm_cuda_chunk_size/16)))
        naesb = nfullaesblock-(i*gcm_cuda_chunk_size/16);
      /* need to recompute grid for each chunk */
      g.y = g.z = 1;
      g.x = gcm_cuda_chunk_size/(256*16);
      g.x *= 1; /* tbp */
      /* problem if g.x >= 65535 ... won't happen (gcm_cuda_chunk_size <= 8*1024*1024 -> g.x <= 2048) */
      fct<<<g,b,0,streams[0]>>>(gin+gcm_cuda_chunk_size/sizeof(uint32_t)*i,
                                gout+gcm_cuda_chunk_size/sizeof(uint32_t)*i,
                                gaes_edrk,naesb,gFT0, gFT1, gFT2, gFT3, gFSb,
                                gIV+4*i);
      CHECK(cudaEventRecord(event[i],streams[0]));
    }
#else
    fct<<<g,b,0,0/*streams[0]*/>>>(gin,gout,gaes_edrk,nfullaesblock, gFT0, gFT1, gFT2, gFT3, gFSb, gIV);
#endif // GCM_CUDA_ENCRYPT_BY_CHUNK
  }
  /* encrypt leftovers */
  memset(temp,0,16);
  memcpy(temp, npub, 12);
  for (i = nfullgpuaesblock*256 ; i < (mlen+15)/16 ; i++) {
    int max;
    ((uint32_t*)temp)[3] = __builtin_bswap32(i+2);
    aes_encrypt((uint32_t*)temp,(uint32_t*)H,aes_edrk);
    max = 16;
    if (mlen-i*16<16)
      max = mlen-i*16;
    for (j = 0 ; j < max; j++) {
      c[i*16+j]=m[i*16+j] ^ H[j];
    }
    dataleft -= max;
  } 
  assert(0 == dataleft);
  /* GCM on AD */
  memset(accum,0,16);
  memset(temp,0,16);
  memset(H,0,16);
  memset(T,0,16);
  memset(fb,0,16);
  aes_encrypt((uint32_t*)temp,(uint32_t*)H,aes_edrk);
  memcpy(temp, npub, 12);
  temp[15] = 1;
  aes_encrypt((uint32_t*)temp,(uint32_t*)T,aes_edrk);
  do_gcm(accum, H, ad, adlen);
#ifdef GCM_CUDA_ENCRYPT_BY_CHUNK
  if (nfullgpuaesblock > 0) {
    for (i = 0 ; i < nchunk ; i++) {
      unsigned long long naesb = gcm_cuda_chunk_size/16;
      if (naesb > (nfullaesblock-(i*gcm_cuda_chunk_size/16)))
        naesb = nfullaesblock-(i*gcm_cuda_chunk_size/16);
      CHECK(cudaEventSynchronize(event[i]));
      CHECK(cudaEventDestroy(event[i]));
      // Here we can't use cudaMemcpy, as it run in the default stream,
      // and therefore will wait for all kernels execution before running
      // the first cudaMemcpy.
      // however, using cudaMemcpyAsync on streams[1] seems to work, despite
      // the fact the call will likely be synchronous.
      CHECK(cudaMemcpyAsync(c+gcm_cuda_chunk_size*i,
                            gout+gcm_cuda_chunk_size/sizeof(uint32_t)*i,naesb*16,cudaMemcpyDeviceToHost,streams[1]));
      CHECK(cudaStreamSynchronize(streams[1]));
#if !defined(GPU_NOXOR)
      do_gcm(accum, H, c+gcm_cuda_chunk_size*i, naesb*16);
#else
      do_xor_gcm(accum, H, c+gcm_cuda_chunk_size*i, m+gcm_cuda_chunk_size*i, naesb*16);
#endif // !GPU_NOXOR
    }
  }
  do_gcm(accum, H, c+nfullaesblock*16, mlen-nfullaesblock*16);
#else
  if (nfullgpuaesblock > 0) {
    CHECK(cudaDeviceSynchronize());
    CHECK(cudaMemcpy(c,gout,nfullgpuaesblock*256*16,cudaMemcpyDeviceToHost));
  }
#if !defined(GPU_NOXOR)
  do_gcm(accum, H, c, mlen);
#else
  do_xor_gcm(accum, H, c, m, mlen);
#endif // !GPU_NOXOR
#endif // GCM_CUDA_ENCRYPT_BY_CHUNK
  (*(unsigned long long*)&fb[0]) = _bswap64((unsigned long long)(8*adlen));
  (*(unsigned long long*)&fb[8]) = _bswap64((unsigned long long)(8*mlen));
  addmul(accum,fb,16,H);
  for (i = 0;i < 16;++i)
    (c+mlen)[i] = T[i] ^ accum[i];
  return 0;
}

/* same interface as the supercop crypto_aead_decrypt()
   functions.
   *But* it requires initialization and clean-up
   */
int crypto_aead_decrypt_cuda(
  unsigned char *m,unsigned long long *outputmlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned long long nfullgpuaesblock =  (clen-16)/(256*16);
  unsigned long long nfullaesblock;
  unsigned long long dataleft;
  uint32_t aes_edrk[64];
  uint32_t aes_edrk_diag[64];
  unsigned char accum[16], H[16], T[16], temp[16], fb[16];
  cudaError_t err;
  int i, j;
  int res = 0;
  dim3 g, b;
  aes_set_key((const unsigned int*)k, aes_edrk);
  {
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
  }
  *outputmlen = clen-16;
  if ((nfullgpuaesblock*256*16) > gcm_cuda_max_size) {
    nfullgpuaesblock = gcm_cuda_max_size/(256*16);
  }
  g.y = g.z = 1;
  g.x = nfullgpuaesblock;
  g.x *= 1; /* tbp */
  while (g.x >= 65536) {
    g.x /= 2;
    g.y *= 2;
  }
  nfullgpuaesblock = g.x*g.y/1;
  nfullaesblock = 256 * nfullgpuaesblock;
  dataleft = (*outputmlen)-(nfullgpuaesblock*256*16);
  b.y = b.z = 1;
  b.x = 256;
  if (nfullgpuaesblock>0) {
  //   CHECK(cudaMemcpyAsync(gaes_edrk,aes_edrk,256,cudaMemcpyHostToDevice,0));
  //   CHECK(cudaMemcpyAsync(gIV,npub,12,cudaMemcpyHostToDevice,0));
  //   CHECK(cudaMemcpyAsync(gin,m,nfullgpuaesblock*256*16,cudaMemcpyHostToDevice,0/*streams[0]*/));
    /* BEWARE which keys are send (diagonalized or not) */
    CHECK(cudaMemcpy(gaes_edrk,aes_edrk_diag,256,cudaMemcpyHostToDevice));
    CHECK(cudaMemset(gIV,0,16));
    CHECK(cudaMemcpy(gIV,npub,12,cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(gin,m,nfullgpuaesblock*256*16,cudaMemcpyHostToDevice));
    aes_gcm_cuda_BTB32DIAGKEY0_PRMT_8coalcoal<<<g,b,0,0/*streams[0]*/>>>(gin,gout,gaes_edrk,nfullaesblock, gFT0, gFT1, gFT2, gFT3, gFSb, gIV);
  }
  /* decrypt leftovers */
  memset(temp,0,16);
  memcpy(temp, npub, 12);
  for (i = nfullgpuaesblock*256 ; i < ((*outputmlen)+15)/16 ; i++) {
    int max;
    ((uint32_t*)temp)[3] = __builtin_bswap32(i+2);
    aes_encrypt((uint32_t*)temp,(uint32_t*)H,aes_edrk);
    max = 16;
    if ((*outputmlen)-i*16<16)
      max = (*outputmlen)-i*16;
    for (j = 0 ; j < max; j++) {
      m[i*16+j]=c[i*16+j] ^ H[j];
    }
    dataleft -= max;
  } 
  assert(0 == dataleft);
  /* GCM on AD */
  memset(accum,0,16);
  memset(temp,0,16);
  memset(H,0,16);
  memset(T,0,16);
  memset(fb,0,16);
  aes_encrypt((uint32_t*)temp,(uint32_t*)H,aes_edrk);
  memcpy(temp, npub, 12);
  temp[15] = 1;
  aes_encrypt((uint32_t*)temp,(uint32_t*)T,aes_edrk);
  do_gcm(accum, H, ad, adlen);
  /* GCM on encrypted (async) */
  do_gcm(accum, H, c, *outputmlen);
  (*(unsigned long long*)&fb[0]) = _bswap64((unsigned long long)(8*adlen));
  (*(unsigned long long*)&fb[8]) = _bswap64((unsigned long long)(8*(*outputmlen)));
  addmul(accum,fb,16,H);
  for (i = 0;i < 16;++i)
    res |= T[i] ^ accum[i];
  if (nfullgpuaesblock > 0) {
    if (!res) {
      CHECK(cudaDeviceSynchronize());
      CHECK(cudaMemcpy(m,gout,nfullgpuaesblock*256*16,cudaMemcpyDeviceToHost));
    } else {
      CHECK(cudaDeviceSynchronize());
      CHECK(cudaMemset(gout,0,nfullgpuaesblock*256*16));
      memset(m,0,(*outputmlen)); // we might have written up to 4095 bytes
    }
  }
  return res;
}
