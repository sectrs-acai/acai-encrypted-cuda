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

#ifndef _AES_GPU_
#define _AES_GPU_

/* this can build a *lot* of different implementation
   of the basic AES encryption function.
   This is mostly macro-based, to avoid to much
   code duplication (and therefore, hard-to-trace bugs).
*/

/* first some support stuff */
#if __CUDA_ARCH__ < 320
/* rotr() is defined in aes_scalar.h */
#define rotr__gpu(x,n) rotr(x,n)
#else
#define rotr__gpu(x,n) __funnelshift_rc(x,x,n)
#endif
/* we don't really need the (untested) funnel shifter,
   since we can do the full-byte rotations with the byte
   permutation instruction for 8, 16 or 24 bits, which
   is all that AES needs. */
__device__ static inline uint32_t rotr8__gpu(const uint32_t x) {
  uint32_t tmp0;
  asm("prmt.b32  %0, %1, %1, %2;" : "=r"(tmp0) : "r"(x), "r"(0x0321));
  return tmp0;
}
__device__ static inline uint32_t rotr16__gpu(const uint32_t x) {
  uint32_t tmp0;
  asm("prmt.b32  %0, %1, %1, %2;" : "=r"(tmp0) : "r"(x), "r"(0x1032));
  return tmp0;
}
__device__ static inline uint32_t rotr24__gpu(const uint32_t x) {
  uint32_t tmp0;
  asm("prmt.b32  %0, %1, %1, %2;" : "=r"(tmp0) : "r"(x), "r"(0x2103));
  return tmp0;
}
/* we can even do the byte-swap (needed to increment the
   byte-reversed counter in CTR/GCM mode) */
__device__ static inline uint32_t bswap32__gpu(const uint32_t x) {
  uint32_t tmp0;
  asm("prmt.b32  %0, %1, %1, %2;" : "=r"(tmp0) : "r"(x), "r"(0x0123));
  return tmp0;
}  
/* __shfl_xor() requires 3.x hardware... here's a slow,
   approximate (no width) emulation for 2.x
   hardware variant untested, so hopefully this implements
   the proper algorithm :-)
*/
#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ < 300)
__device__ static inline int __shfl_xor(const int x, const int mask) {
  __shared__ int temp[256]; // 256 threads only !
  int r;
  __syncthreads();
  temp[threadIdx.x] = x;
  __syncthreads();
  r = temp[threadIdx.x ^ mask];
  __syncthreads();
  return r;
}
__device__ static inline int __shfl(const int x, const int src) {
  __shared__ int temp[256]; // 256 threads only !
  int r;
  __syncthreads();
  temp[threadIdx.x] = x;
  __syncthreads();
  r = temp[src];
  __syncthreads();
  return r;
}
#endif

#ifdef DO_TIMING_IN_GPU
#define TBEGIN                                              \
  long long int tc0 = clock64(), tc1;                       \
  long long int tn0, tn1;                                   \
  asm("mov.u64  %0,%%globaltimer;" : "=l" (tn0))
#define TEND                                            \
  tc1 = clock64();                                      \
  asm("mov.u64  %0,%%globaltimer;" : "=l" (tn1));       \
  if (tx == 0) printf("%lld clocks, %lld ns: %lf GHz\n", \
                      (tc1-tc0), (tn1-tn0), ((double)(tc1-tc0))/((double)(tn1-tn0)))
#else
#define TBEGIN
#define TEND
#endif

/* function lists */
#ifdef __cplusplus
extern "C" {
#endif
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
#ifdef __cplusplus
}
#endif

/* pick between pre-rotated FTs (FT1, FT2, FT3)
   and rotation, normally using prmt.b32 to implement
   full-byte rotation.
   Which implementation to use is selected later.
*/
#define LK0a(Y)      sFT0[(Y    )&0xFF]

#define LK1a(Y)      sFT1[(Y>> 8)&0xFF]
#define LK1b(Y) rotr__gpu(sFT0[(Y>> 8)&0xFF],24)
#define LK1c(Y) rotr24__gpu(sFT0[(Y>> 8)&0xFF])

#define LK2a(Y)      sFT2[(Y>>16)&0xFF]
#define LK2b(Y) rotr__gpu(sFT0[(Y>>16)&0xFF],16)
#define LK2c(Y) rotr16__gpu(sFT0[(Y>>16)&0xFF])

#define LK3a(Y)      sFT3[(Y>>24)&0xFF]
#define LK3b(Y) rotr__gpu(sFT1[(Y>>24)&0xFF],16)
#define LK3c(Y) rotr__gpu(sFT0[(Y>>24)&0xFF], 8)
#define LK3d(Y) rotr16__gpu(sFT1[(Y>>24)&0xFF])
#define LK3e(Y) rotr8__gpu(sFT0[(Y>>24)&0xFF])

/* a pair of FT-based AES round. A,B,C,D are lowercase
   character to pickup some of the macro above, i.e.
   choosing the number of tables (1, 2 or 4) and the
   type of rotate (always use permute, shifts are
   slower :-).
   The difference between the two is only the interleaving
   of computations exposed to the compiler. Doesn't change
   much in practice.
*/
#define AES_ROUND_CUDA_FT_SEQ(A,B,C,D,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)   \
    {                                                           \
      X0  = LK0##A(Y0);                                         \
      X0 ^= LK1##B(Y1);                                         \
      X0 ^= LK2##C(Y2);                                         \
      X0 ^= LK3##D(Y3);                                         \
                                                                \
      X1  = LK0##A(Y1);                                         \
      X1 ^= LK1##B(Y2);                                         \
      X1 ^= LK2##C(Y3);                                         \
      X1 ^= LK3##D(Y0);                                         \
                                                                \
      X2  = LK0##A(Y2);                                         \
      X2 ^= LK1##B(Y3);                                         \
      X2 ^= LK2##C(Y0);                                         \
      X2 ^= LK3##D(Y1);                                         \
                                                                \
      X3  = LK0##A(Y3);                                         \
      X3 ^= LK1##B(Y0);                                         \
      X3 ^= LK2##C(Y1);                                         \
      X3 ^= LK3##D(Y2);                                         \
                                                                \
      X0 ^= (KEY[I+0]);                                         \
      X1 ^= (KEY[I+1]);                                         \
      X2 ^= (KEY[I+2]);                                         \
      X3 ^= (KEY[I+3]);                                         \
                                                                \
      Y0=X0;                                                    \
      Y1=X1;                                                    \
      Y2=X2;                                                    \
      Y3=X3;                                                    \
    }

#define AES_ROUND_CUDA_FT_INT(A,B,C,D,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)   \
    {                                                           \
      X0  = LK0##A(Y0);                                         \
      X1  = LK0##A(Y1);                                         \
      X2  = LK0##A(Y2);                                         \
      X3  = LK0##A(Y3);                                         \
                                                                \
      X0 ^= LK1##B(Y1);                                         \
      X1 ^= LK1##B(Y2);                                         \
      X2 ^= LK1##B(Y3);                                         \
      X3 ^= LK1##B(Y0);                                         \
                                                                \
      X0 ^= LK2##C(Y2);                                         \
      X1 ^= LK2##C(Y3);                                         \
      X2 ^= LK2##C(Y0);                                         \
      X3 ^= LK2##C(Y1);                                         \
                                                                \
      X0 ^= LK3##D(Y3);                                         \
      X1 ^= LK3##D(Y0);                                         \
      X2 ^= LK3##D(Y1);                                         \
      X3 ^= LK3##D(Y2);                                         \
                                                                \
      X0 ^= (KEY[I+0]);                                         \
      X1 ^= (KEY[I+1]);                                         \
      X2 ^= (KEY[I+2]);                                         \
      X3 ^= (KEY[I+3]);                                         \
                                                                \
      Y0=X0;                                                    \
      Y1=X1;                                                    \
      Y2=X2;                                                    \
      Y3=X3;                                                    \
    }

/* 1/4 of a pure SBOX phase, on standard input using standard SBOX */
#define AES_ROUND_CUDA_SBOX(X,Y)                                       \
  X =                                                                  \
    ( sFSb[(Y      ) &0xFF ]       ) |                                 \
    ( sFSb[(Y >>  8) &0xFF ] <<  8 ) |                                 \
    ( sFSb[(Y >> 16) &0xFF ] << 16 ) |                                 \
    ( sFSb[(Y >> 24) &0xFF ] << 24 )

/* SBOX phase, on diagonalized input. */
#define AES_ROUND_CUDA_SBOX_DIAG(X0,X1,X2,X3,Y0,Y1,Y2,Y3)               \
    X0 =                                                                \
      ( sFSb[(Y0 >> 24) &0xFF ]       ) |                               \
      ( sFSb[(Y1 >> 24) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y2 >> 24) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y3 >> 24) &0xFF ] << 24 );                                \
    X1 =                                                                \
      ( sFSb[(Y1 >> 16) &0xFF ]       ) |                               \
      ( sFSb[(Y2 >> 16) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y3 >> 16) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y0 >> 16) &0xFF ] << 24 );                                \
    X2 =                                                                \
      ( sFSb[(Y2 >>  8) &0xFF ]       ) |                               \
      ( sFSb[(Y3 >>  8) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y0 >>  8) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y1 >>  8) &0xFF ] << 24 );                                \
    X3 =                                                                \
      ( sFSb[(Y3      ) &0xFF ]       ) |                               \
      ( sFSb[(Y0      ) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y1      ) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y2      ) &0xFF ] << 24 )

/* SBOX phase w/SR on standard input. */
#define AES_ROUND_CUDA_SBOX_SR(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                 \
  X0 =                                                                  \
    ( sFSb[(Y0      ) &0xFF ] << 24 ) |                                 \
    ( sFSb[(Y0 >>  8) &0xFF ]       ) |                                 \
    ( sFSb[(Y0 >> 16) &0xFF ] <<  8 ) |                                 \
    ( sFSb[(Y0 >> 24) &0xFF ] << 16 );                                  \
  X1 =                                                                  \
    ( sFSb[(Y1      ) &0xFF ] << 16 ) |                                 \
    ( sFSb[(Y1 >>  8) &0xFF ] << 24 ) |                                 \
    ( sFSb[(Y1 >> 16) &0xFF ]       ) |                                 \
    ( sFSb[(Y1 >> 24) &0xFF ] <<  8 );                                  \
  X2 =                                                                  \
    ( sFSb[(Y2      ) &0xFF ] <<  8 ) |                                 \
    ( sFSb[(Y2 >>  8) &0xFF ] << 16 ) |                                 \
    ( sFSb[(Y2 >> 16) &0xFF ] << 24 ) |                                 \
    ( sFSb[(Y2 >> 24) &0xFF ]       );                                  \
  X3 =                                                                  \
    ( sFSb[(Y3      ) &0xFF ]       ) |                                 \
    ( sFSb[(Y3 >>  8) &0xFF ] <<  8 ) |                                 \
    ( sFSb[(Y3 >> 16) &0xFF ] << 16 ) |                                 \
    ( sFSb[(Y3 >> 24) &0xFF ] << 24 )
  
/* SBOX phase w/SR, on diagonalized input. */
#define AES_ROUND_CUDA_SBOX_DIAG_SR(X0,X1,X2,X3,Y0,Y1,Y2,Y3)            \
    X0 =                                                                \
      ( sFSb[(Y0 >> 24) &0xFF ] << 24 ) |                               \
      ( sFSb[(Y1 >> 24) &0xFF ]       ) |                               \
      ( sFSb[(Y2 >> 24) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y3 >> 24) &0xFF ] << 16 );                                \
    X1 =                                                                \
      ( sFSb[(Y1 >> 16) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y2 >> 16) &0xFF ] << 24 ) |                               \
      ( sFSb[(Y3 >> 16) &0xFF ]       ) |                               \
      ( sFSb[(Y0 >> 16) &0xFF ] <<  8 );                                \
    X2 =                                                                \
      ( sFSb[(Y2 >>  8) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y3 >>  8) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y0 >>  8) &0xFF ] << 24 ) |                               \
      ( sFSb[(Y1 >>  8) &0xFF ]       );                                \
    X3 =                                                                \
      ( sFSb[(Y3      ) &0xFF ]       ) |                               \
      ( sFSb[(Y0      ) &0xFF ] <<  8 ) |                               \
      ( sFSb[(Y1      ) &0xFF ] << 16 ) |                               \
      ( sFSb[(Y2      ) &0xFF ] << 24 )

/* a pure SBOX phase, 16 bits texture.
   *slow* in practice. Texture don't seem to like random access... 
 */
#define AES_ROUND_CUDA_SBOX_T2(X,Y)                                    \
  {                                                                    \
    /*X = (tex1D(tFSbSq,(float)(Y & 0xFFFF))      ) |                  \
      (tex1D(tFSbSq,(float)(Y >> 16)) << 16);*/                         \
    X = (tex1Dfetch(tFSbSq,(int)(Y & 0xFFFF))      ) |                  \
      (tex1Dfetch(tFSbSq,(int)(Y >> 16)) << 16);                        \
  }

/* This transpose a 4x4 matrix */
#define TRANSPOSE(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                              \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp0) : "r"(Y0), "r"(Y1), "r"(0x3715)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp1) : "r"(Y2), "r"(Y3), "r"(0x3715)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp2) : "r"(Y0), "r"(Y1), "r"(0x2604)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp3) : "r"(Y2), "r"(Y3), "r"(0x2604)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X0) : "r"(tmp0), "r"(tmp1), "r"(0x3276)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X1) : "r"(tmp2), "r"(tmp3), "r"(0x3276)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X2) : "r"(tmp0), "r"(tmp1), "r"(0x1054)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X3) : "r"(tmp2), "r"(tmp3), "r"(0x1054)); \
  }
/* type 1 diagonalization
in:     0x00010203
        0x04050607
        0x08090a0b
        0x0c0d0e0f

out:    0x0304090e
        0x0207080d
        0x01060b0c
        0x00050a0f
 */
#define DIAG1(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                  \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp0) : "r"(Y0), "r"(Y1), "r"(0x0714)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp1) : "r"(Y0), "r"(Y1), "r"(0x2536)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp2) : "r"(Y2), "r"(Y3), "r"(0x0714)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp3) : "r"(Y2), "r"(Y3), "r"(0x2536)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X0) : "r"(tmp0), "r"(tmp3), "r"(0x3276)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X1) : "r"(tmp0), "r"(tmp3), "r"(0x1054)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X2) : "r"(tmp1), "r"(tmp2), "r"(0x3276)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X3) : "r"(tmp1), "r"(tmp2), "r"(0x1054)); \
  }
/* type 2 diagonalization
in:     0x00010203
        0x04050607
        0x08090a0b
        0x0c0d0e0f

out:    0x0c090603
        0x000d0a07
        0x04010e0b
        0x0805020f
 */
#define DIAG2(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                  \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp0) : "r"(Y0), "r"(Y1), "r"(0x7250)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp1) : "r"(Y2), "r"(Y3), "r"(0x7250)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp2) : "r"(Y0), "r"(Y3), "r"(0x3614)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp3) : "r"(Y2), "r"(Y1), "r"(0x3614)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X0) : "r"(tmp0), "r"(tmp1), "r"(0x7610)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X1) : "r"(tmp2), "r"(tmp3), "r"(0x3254)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X2) : "r"(tmp0), "r"(tmp1), "r"(0x3254)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X3) : "r"(tmp2), "r"(tmp3), "r"(0x7610)); \
  }
/* type 1 undiagonalization (inverse of DIAG1)
in:     0x00010203
        0x04050607
        0x08090a0b
        0x0c0d0e0f

out:    0x0c080400
        0x010d0905
        0x06020e0a
        0x0b07030f
*/
#define UNDIAG1(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                 \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp0) : "r"(Y0), "r"(Y1), "r"(0x7351)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp1) : "r"(Y0), "r"(Y1), "r"(0x6240)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp2) : "r"(Y2), "r"(Y3), "r"(0x7351)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(tmp3) : "r"(Y2), "r"(Y3), "r"(0x6240)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X0) : "r"(tmp0), "r"(tmp2), "r"(0x7632)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X1) : "r"(tmp1), "r"(tmp3), "r"(0x2763)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X2) : "r"(tmp0), "r"(tmp2), "r"(0x1054)); \
    asm("prmt.b32  %0, %1, %2, %3;" : "=r"(X3) : "r"(tmp1), "r"(tmp3), "r"(0x4105)); \
  }

/* Galois field "times 2" on low 8 bits of a 32 bits register */
#define GMUL2_0(Y)                          \
  ((Y<<1) ^ (0x011b & (Y&0x0080 ? 0x01FF:0x0000)))
/* Galois field "times 3" on low 8 bits of a 32 bits register */
#define GMUL3_0(Y)                                  \
  (Y ^ (Y<<1) ^ (0x011b & (Y&0x0080 ? 0x01FF:0x0000)))
/* Byte extraction... */
#define B(Y,o) ((Y>>o)&0xFF)

/* Galois field "times 2" on 4x 8 bits elements in a 32 bits register
   two implementations, for SM2x and SM3+ (last one untested)..
   SM_50 is missing both the mul32 from both & the vset4 from SM_30 ...
 */
#define GMUL2_SM20(X,Y)                         \
  {                                             \
    uint32_t Ys1 = Y << 1;                      \
    uint32_t Ys1m = Ys1 & 0xFEFEFEFE;           \
    uint32_t Ysm = (Y & 0x80808080) >> 7;       \
    uint32_t Ysx = Ysm * 0x01b;                 \
    X = Ys1m ^ Ysx;                             \
  }

#define GMUL2_SM30(X,Y)							\
  {									\
    uint32_t Ys1 = Y << 1;						\
    uint32_t Ys1m = Ys1 & 0xFEFEFEFE;					\
    uint32_t Ysm;                                                       \
    asm("vset4.u32.u32.ge %0, %1, %2, %3;" : "=r"(Ysm) : "r"(Y), "r"(0x80808080), "r"(0)); \
    uint32_t Ysx = Ysm * 0x01b;						\
    X = Ys1m ^ Ysx;                                                     \
  }

#if __CUDA_ARCH__ < 300
#define GMUL2(X,Y) GMUL2_SM20(X,Y)
#else
#define GMUL2(X,Y) GMUL2_SM30(X,Y)
#endif

/* MC0-MC3: All 4 by-the-book mix columns on 8 bits element
   (with shift rows included in the byte extraction) */
#define MC0(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                    \
  {                                                                     \
    X0  = (GMUL2_0(B(Y0, 0)) ^ GMUL3_0(B(Y1, 8)) ^ B(Y2,16) ^ B(Y3,24)) << 0; \
    X1  = (GMUL2_0(B(Y0,24)) ^ GMUL3_0(B(Y1, 0)) ^ B(Y2, 8) ^ B(Y3,16)) << 24; \
    X2  = (GMUL2_0(B(Y0,16)) ^ GMUL3_0(B(Y1,24)) ^ B(Y2, 0) ^ B(Y3, 8)) << 16; \
    X3  = (GMUL2_0(B(Y0, 8)) ^ GMUL3_0(B(Y1,16)) ^ B(Y2,24) ^ B(Y3, 0)) << 8; \
  }
#define MC1(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                    \
  {                                                                     \
    X0 |= (B(Y0, 0) ^ GMUL2_0(B(Y1, 8)) ^ GMUL3_0(B(Y2,16)) ^ B(Y3,24)) << 8; \
    X1 |= (B(Y0,24) ^ GMUL2_0(B(Y1, 0)) ^ GMUL3_0(B(Y2, 8)) ^ B(Y3,16)) << 0; \
    X2 |= (B(Y0,16) ^ GMUL2_0(B(Y1,24)) ^ GMUL3_0(B(Y2, 0)) ^ B(Y3, 8)) << 24; \
    X3 |= (B(Y0, 8) ^ GMUL2_0(B(Y1,16)) ^ GMUL3_0(B(Y2,24)) ^ B(Y3, 0)) << 16; \
  }
#define MC2(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                    \
  {                                                                     \
    X0 |= (B(Y0, 0) ^ B(Y1, 8) ^ GMUL2_0(B(Y2,16)) ^ GMUL3_0(B(Y3,24))) << 16; \
    X1 |= (B(Y0,24) ^ B(Y1, 0) ^ GMUL2_0(B(Y2, 8)) ^ GMUL3_0(B(Y3,16))) << 8; \
    X2 |= (B(Y0,16) ^ B(Y1,24) ^ GMUL2_0(B(Y2, 0)) ^ GMUL3_0(B(Y3, 8))) << 0; \
    X3 |= (B(Y0, 8) ^ B(Y1,16) ^ GMUL2_0(B(Y2,24)) ^ GMUL3_0(B(Y3, 0))) << 24; \
  }
#define MC3(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                    \
  {                                                                     \
    X0 |= (GMUL3_0(B(Y0, 0)) ^ B(Y1, 8) ^ B(Y2,16) ^ GMUL2_0(B(Y3,24))) << 24; \
    X1 |= (GMUL3_0(B(Y0,24)) ^ B(Y1, 0) ^ B(Y2, 8) ^ GMUL2_0(B(Y3,16))) << 16; \
    X2 |= (GMUL3_0(B(Y0,16)) ^ B(Y1,24) ^ B(Y2, 0) ^ GMUL2_0(B(Y3, 8))) << 8; \
    X3 |= (GMUL3_0(B(Y0, 8)) ^ B(Y1,16) ^ B(Y2,24) ^ GMUL2_0(B(Y3, 0))) << 0; \
  }

/* 32 bits shift-rows/mix-columns
   Each input variable is only needed in one rotation.
   Each variables MC holds the 4 bytes equivalent to one
   of the macro above. We only need to undiagonalize
   afterward (it's type 1 in the notation above).
   We only multiply by 2 and then do the extra XOR rather
   than multiplying by 3 - no need for the compiler to do
   the CSE...
*/
#define MCF(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                     \
  {                                                      \
    uint32_t Y0t2r;                                      \
    uint32_t Y1t2r;                                      \
    uint32_t Y2t2r;                                      \
    uint32_t Y3t2;                                       \
    uint32_t Y0r = rotr8__gpu(Y0);                       \
    uint32_t Y1r = rotr16__gpu(Y1);                      \
    uint32_t Y2r = rotr24__gpu(Y2);                      \
    GMUL2(Y0t2r,Y0r)                                     \
    GMUL2(Y1t2r,Y1r)                                     \
    GMUL2(Y2t2r,Y2r)                                     \
    GMUL2(Y3t2,Y3)                                       \
    uint32_t MC0 = Y0t2r ^ Y1t2r ^ Y2r ^ Y3 ^ Y1r;       \
    uint32_t MC1 = Y0r ^ Y1t2r ^ Y2t2r ^ Y3 ^ Y2r;       \
    uint32_t MC2 = Y0r ^ Y1r ^ Y2t2r ^ Y3t2 ^ Y3;        \
    uint32_t MC3 = Y0t2r ^ Y1r ^ Y2r ^ Y3t2 ^ Y0r;       \
    UNDIAG1(X0,X1,X2,X3,MC0,MC1,MC2,MC3)                 \
  }
/* same but no SR */
#define MCFNOSR(X0,X1,X2,X3,Y0r,Y1r,Y2r,Y3)              \
  {                                                      \
    uint32_t Y0t2r;                                      \
    uint32_t Y1t2r;                                      \
    uint32_t Y2t2r;                                      \
    uint32_t Y3t2;                                       \
    GMUL2(Y0t2r,Y0r)                                     \
    GMUL2(Y1t2r,Y1r)                                     \
    GMUL2(Y2t2r,Y2r)                                     \
    GMUL2(Y3t2,Y3)                                       \
    uint32_t MC0 = Y0t2r ^ Y1t2r ^ Y2r ^ Y3 ^ Y1r;       \
    uint32_t MC1 = Y0r ^ Y1t2r ^ Y2t2r ^ Y3 ^ Y2r;       \
    uint32_t MC2 = Y0r ^ Y1r ^ Y2t2r ^ Y3t2 ^ Y3;        \
    uint32_t MC3 = Y0t2r ^ Y1r ^ Y2r ^ Y3t2 ^ Y0r;       \
    UNDIAG1(X0,X1,X2,X3,MC0,MC1,MC2,MC3)                 \
  }

/* Almost by-the-book AES round (0 FT) built using the macros above */
#define AES_ROUND_CUDA_BTB0(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)              \
  {                                                                     \
    /* sbox */                                                          \
    AES_ROUND_CUDA_SBOX(X0,Y0);                                         \
    AES_ROUND_CUDA_SBOX(X1,Y1);                                         \
    AES_ROUND_CUDA_SBOX(X2,Y2);                                         \
    AES_ROUND_CUDA_SBOX(X3,Y3);                                         \
    /* shift rows + mix columns */                                      \
    MC0(Y0,Y1,Y2,Y3,X0,X1,X2,X3)                                        \
    MC1(Y0,Y1,Y2,Y3,X0,X1,X2,X3)                                        \
    MC2(Y0,Y1,Y2,Y3,X0,X1,X2,X3)                                        \
    MC3(Y0,Y1,Y2,Y3,X0,X1,X2,X3)                                        \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }

/* Almost by-the-book AES round, with 32 bits MC/SR (0 FT) */
#define AES_ROUND_CUDA_BTB320(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)            \
  {                                                                     \
    /* sbox */                                                          \
    AES_ROUND_CUDA_SBOX(X0,Y0);                                         \
    AES_ROUND_CUDA_SBOX(X1,Y1);                                         \
    AES_ROUND_CUDA_SBOX(X2,Y2);                                         \
    AES_ROUND_CUDA_SBOX(X3,Y3);                                         \
    /* shift rows + mix columns */                                      \
    MCF(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                                       \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }
/* Almost by-the-book AES round, with 32 bits MC/SR (0 FT), SR in SBOX */
#define AES_ROUND_CUDA_BTB32SR0(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)          \
  {                                                                     \
    /* sbox + shiftrows */                                              \
    AES_ROUND_CUDA_SBOX_SR(X0,X1,X2,X3,Y0,Y1,Y2,Y3);                    \
    /* mix columns */                                                   \
    MCFNOSR(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                                   \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }

/* same as MCF, but without the undiagonalization.
 */ 
#define MCFDIAGKEY(X0,X1,X2,X3,Y0,Y1,Y2,Y3)              \
  {                                                      \
    uint32_t Y0t2r;                                      \
    uint32_t Y1t2r;                                      \
    uint32_t Y2t2r;                                      \
    uint32_t Y3t2;                                       \
    uint32_t Y0r = rotr8__gpu(Y0);                       \
    uint32_t Y1r = rotr16__gpu(Y1);                      \
    uint32_t Y2r = rotr24__gpu(Y2);                      \
    GMUL2(Y0t2r,Y0r);                                    \
    GMUL2(Y1t2r,Y1r);                                    \
    GMUL2(Y2t2r,Y2r);                                    \
    GMUL2(Y3t2,Y3);                                      \
    X0 = Y0t2r ^ Y1t2r ^ Y2r ^ Y3 ^ Y1r;                 \
    X1 = Y0r ^ Y1t2r ^ Y2t2r ^ Y3 ^ Y2r;                 \
    X2 = Y0r ^ Y1r ^ Y2t2r ^ Y3t2 ^ Y3;                  \
    X3 = Y0t2r ^ Y1r ^ Y2r ^ Y3t2 ^ Y0r;                 \
  }
/* same as MCFNOSR, but without the undiagonalization.
 */ 
#define MCFNOSRDIAGKEY(X0,X1,X2,X3,Y0r,Y1r,Y2r,Y3)       \
  {                                                      \
    uint32_t Y0t2r;                                      \
    uint32_t Y1t2r;                                      \
    uint32_t Y2t2r;                                      \
    uint32_t Y3t2;                                       \
    GMUL2(Y0t2r,Y0r);                                    \
    GMUL2(Y1t2r,Y1r);                                    \
    GMUL2(Y2t2r,Y2r);                                    \
    GMUL2(Y3t2,Y3);                                      \
    X0 = Y0t2r ^ Y1t2r ^ Y2r ^ Y3 ^ Y1r;                 \
    X1 = Y0r ^ Y1t2r ^ Y2t2r ^ Y3 ^ Y2r;                 \
    X2 = Y0r ^ Y1r ^ Y2t2r ^ Y3t2 ^ Y3;                  \
    X3 = Y0t2r ^ Y1r ^ Y2r ^ Y3t2 ^ Y0r;                 \
  }

/* diagonalize input before first round.
   can be avoided by using non-diagonal
   SBOX during first round */
#define PREROUNDS_DIAGKEY(X0,X1,X2,X3)          \
  {                                             \
    uint32_t T0=X0,T1=X1,T2=X2,T3=X3;           \
    DIAG1(X0,X1,X2,X3,T0,T1,T2,T3);              \
  }
/* undiagonalize after last round.
   can be avoided by doing a custom finish,
   using the diagonalized data */
#define POSTROUNDS_DIAGKEY(X0,X1,X2,X3)         \
  {                                             \
    uint32_t T0=X0,T1=X1,T2=X2,T3=X3;           \
    UNDIAG1(X0,X1,X2,X3,T0,T1,T2,T3);            \
  }
/* AES round using MCFDIAGKEY & pre-diagonalized key */
#define AES_ROUND_CUDA_BTB32DIAGKEY0(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  {                                                                     \
    /* sbox */                                                          \
    AES_ROUND_CUDA_SBOX_DIAG(X0,X1,X2,X3,Y0,Y1,Y2,Y3);                  \
    /* shift rows + mix columns */                                      \
    MCFDIAGKEY(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                                \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }
/* AES round using MCFNOSRDIAGKEY & pre-diagonalized key */
#define AES_ROUND_CUDA_BTB32SRDIAGKEY0(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)   \
  {                                                                     \
    /* sbox + shiftrow */                                               \
    AES_ROUND_CUDA_SBOX_DIAG_SR(X0,X1,X2,X3,Y0,Y1,Y2,Y3);               \
    /* mix columns */                                                   \
    MCFNOSRDIAGKEY(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                            \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }

/* by-the-book AES round, with 32 bits MC/SR (0 FT) & textured 16 bits Sbox
   *slow* !
 */
#define AES_ROUND_CUDA_BTB32T20(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)          \
  {                                                                     \
    /* sbox */                                                          \
    AES_ROUND_CUDA_SBOX_T2(X0,Y0);                                      \
    AES_ROUND_CUDA_SBOX_T2(X1,Y1);                                      \
    AES_ROUND_CUDA_SBOX_T2(X2,Y2);                                      \
    AES_ROUND_CUDA_SBOX_T2(X3,Y3);                                      \
    /* shift rows + mix columns */                                      \
    MCF(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                                       \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }

/* by-the-book AES round, with 32 bits MC/SR (0 FT) & textured 16 bits Sbox for half the accesses
 *slow* !
 */  
#define AES_ROUND_CUDA_BTB32T2H0(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)          \
  {                                                                     \
    /* sbox */                                                          \
    AES_ROUND_CUDA_SBOX_T2(X0,Y0);                                      \
    AES_ROUND_CUDA_SBOX(X1,Y1);                                         \
    AES_ROUND_CUDA_SBOX_T2(X2,Y2);                                      \
    AES_ROUND_CUDA_SBOX(X3,Y3);                                         \
    /* shift rows + mix columns */                                      \
    MCF(Y0,Y1,Y2,Y3,X0,X1,X2,X3);                                       \
    Y0 ^= (KEY[I+0]);                                                   \
    Y1 ^= (KEY[I+1]);                                                   \
    Y2 ^= (KEY[I+2]);                                                   \
    Y3 ^= (KEY[I+3]);                                                   \
  }

/* 8 different AES rounds, using 1/2/4 FTs, either sequential
   or interleaved.
*/
#define AES_ROUND_CUDA_FT_SEQ1(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_SEQ(a,c,c,e,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

#define AES_ROUND_CUDA_FT_SEQ2(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_SEQ(a,a,c,d,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

#define AES_ROUND_CUDA_FT_SEQ4(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_SEQ(a,a,a,a,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

#define AES_ROUND_CUDA_FT_INT1(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_INT(a,c,c,e,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

#define AES_ROUND_CUDA_FT_INT2(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_INT(a,a,c,d,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

#define AES_ROUND_CUDA_FT_INT4(KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)  \
  AES_ROUND_CUDA_FT_INT(a,a,a,a,KEY,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)

/* unrolling macros */
#define MAKE0(X)
#define MAKE1(X)                                \
  X(0)
#define MAKE2(X)                                \
  X(0);X(1)
#define MAKE3(X)                                \
  X(0);X(1);X(2)
#define MAKE4(X)                                \
  X(0);X(1);X(2);X(3)

/* Define and load an FT in shared memory */
#define DEFINE_SFT(A)                            \
  __shared__ uint32_t sFT##A[256]
#define LOAD_SFT(A)                              \
  sFT##A[tx] = gFT##A[tx]

/* last round of AES in pure C */
#define AES_LASTROUND_CUDA_C(Y,X0,X1,X2,X3)                             \
  Y = (saes_edrk[i++]) ^                                                \
    ( sFSb[( X0       ) &0xFF ]       ) ^                               \
    ( sFSb[( X1 >>  8 ) &0xFF ] <<  8 ) ^                               \
    ( sFSb[( X2 >> 16 ) &0xFF ] << 16 ) ^                               \
    ( sFSb[( X3 >> 24 ) &0xFF ] << 24 )

/* last round of AES using the permute instruction (works with 8 or 32 bits SBOX) */
#define AES_LASTROUND_CUDA_PRMT(Y,X0,X1,X2,X3)                          \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    tmp0 = sFSb[( X0       ) &0xFF ];                                   \
    tmp1 = sFSb[( X1 >>  8 ) &0xFF ];                                   \
    tmp2 = sFSb[( X2 >> 16 ) &0xFF ];                                   \
    tmp3 = sFSb[( X3 >> 24 ) &0xFF ];                                   \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp0) : "r"(tmp1), "r"(0x0040)); \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp2) : "r"(tmp3), "r"(0x4000)); \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp0) : "r"(tmp2), "r"(0x7610)); \
    Y = saes_edrk[i++] ^ tmp0;                                          \
  }

/* last round of AES, using a 8 bits SBOX loaded as 32 bits. */
#define AES_LASTROUND_CUDA_PRMT8AS32(Y,X0,X1,X2,X3)                     \
  {                                                                     \
    uint32_t tmp0, tmp1, tmp2, tmp3;                                    \
    uint32_t i0, i1, i2, i3;                                            \
    tmp0 = sFSb32[( X0 >>  2 ) &0x3F ];                                 \
    tmp1 = sFSb32[( X1 >> 10 ) &0x3F ];                                 \
    tmp2 = sFSb32[( X2 >> 18 ) &0x3F ];                                 \
    tmp3 = sFSb32[( X3 >> 26 ) &0x3F ];                                 \
    i0 = ((X0    ) & 0x3);                                            \
    i1 = ((X1>> 8) & 0x3);                                            \
    i2 = ((X2>>16) & 0x3);                                            \
    i3 = ((X3>>24) & 0x3);                                            \
    i0 = i0 | (0x0040+(i1 << 4));                                       \
    i2 = (i2 | (0x0040+(i3 << 4))) << 8;                                \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp0) : "r"(tmp1), "r"(i0)); \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp2) : "r"(tmp3), "r"(i2)); \
    asm("prmt.b32  %0, %0, %1, %2;" : "+r"(tmp0) : "r"(tmp2), "r"(0x7610)); \
    Y = saes_edrk[i++] ^ tmp0;                                          \
  }

/* used a a shortcut by some non-macro implementation */
#define AES_LASTROUND_CUDA(Y,X0,X1,X2,X3) AES_LASTROUND_CUDA_PRMT(Y,X0,X1,X2,X3)

/* load data in ECB mode */
#define START_encrypt                           \
  X0 = input[0] ^ saes_edrk[0];                 \
  X1 = input[1] ^ saes_edrk[1];                 \
  X2 = input[2] ^ saes_edrk[2];                 \
  X3 = input[3] ^ saes_edrk[3]

/* load data in CTR mode */
#define START_ctr                                                       \
  uint32_t T = bswap32__gpu(IV[3]);                                     \
  X0 = IV[0];                                                           \
  X1 = IV[1];                                                           \
  X2 = IV[2];                                                           \
  X3 = T+b;                                                             \
  if (X3 < T) {                                                         \
    X2 =  bswap32__gpu(bswap32__gpu(X2)+1);                             \
    if (!X2) {                                                          \
      X1 =  bswap32__gpu(bswap32__gpu(X1)+1);                           \
      if (!X1) {                                                        \
        X0 =  bswap32__gpu(bswap32__gpu(X0)+1);                         \
      }                                                                 \
    }                                                                   \
  }                                                                     \
  X3 = bswap32__gpu(X3);                                                \
  X0 = X0 ^ saes_edrk[0];                                               \
  X1 = X1 ^ saes_edrk[1];                                               \
  X2 = X2 ^ saes_edrk[2];                                               \
  X3 = X3 ^ saes_edrk[3]

/* load data in GCM mode */
#define START_gcm                                                       \
  uint32_t T = bswap32__gpu(IV[3]);                                     \
  X0 = IV[0];                                                           \
  X1 = IV[1];                                                           \
  X2 = IV[2];                                                           \
  X3 = T+b+2;                                                           \
  X3 = bswap32__gpu(X3);                                                \
  X0 = X0 ^ saes_edrk[0];                                               \
  X1 = X1 ^ saes_edrk[1];                                               \
  X2 = X2 ^ saes_edrk[2];                                               \
  X3 = X3 ^ saes_edrk[3]

#define START_gcmnoxor START_gcm

/* store data in ECB mode */
#define FINISH_encrypt    \
  output[0] = Y0;         \
  output[1] = Y1;         \
  output[2] = Y2;         \
  output[3] = Y3

/* store data in CTR mode */
#define FINISH_ctr                                                      \
  output[0] = Y0 ^ input[0];                                            \
  output[1] = Y1 ^ input[1];                                            \
  output[2] = Y2 ^ input[2];                                            \
  output[3] = Y3 ^ input[3] 

/* store data in GCM mode */
#define FINISH_gcm FINISH_ctr

#define FINISH_gcmnoxor                                      \
  output[0] = Y0;                                            \
  output[1] = Y1;                                            \
  output[2] = Y2;                                            \
  output[3] = Y3

/* define input and output pointers. */
/* no explicit coalescing : direct use of global memory */
#define DEFINECOAL_nocoal_nocoal                \
  const uint32_t *input = all_input + 4*b;      \
  uint32_t *output = all_output + 4*b
/* with no coalescing, we only need to syncthreads for stuff like the keys */
#define INITCOAL_nocoal                  \
  __syncthreads()
/* nothing at the end if no store coalescing */
#define FINISHCOAL_nocoal

/* explicit coalescing w/o shuffle: go through shared memory for at least one */
#define DEFINECOAL_coal_coal                                \
  __shared__ uint32_t buffer[1024];                         \
  const uint32_t *input = buffer+tx*4;                      \
  uint32_t *output = buffer+tx*4
#define DEFINECOAL_coal_nocoal                              \
  __shared__ uint32_t buffer[1024];                         \
  const uint32_t *input = buffer+tx*4;                      \
  uint32_t *output = all_output + 4*b
#define DEFINECOAL_nocoal_coal                              \
  __shared__ uint32_t buffer[1024];                         \
  const uint32_t *input = all_input + 4*b;                  \
  uint32_t *output = buffer+tx*4
/* load coalescing: load global in shared buffer, sync */
#define INITCOAL_coal                             \
  buffer[tx    ] = all_input[4*bb+tx    ];        \
  buffer[tx+256] = all_input[4*bb+tx+256];        \
  buffer[tx+512] = all_input[4*bb+tx+512];        \
  buffer[tx+768] = all_input[4*bb+tx+768];        \
  __syncthreads()
/* store coalescing: buffer to global */
#define FINISHCOAL_coal                           \
  __syncthreads();                                \
  all_output[4*bb+tx    ] = buffer[tx    ];       \
  all_output[4*bb+tx+256] = buffer[tx+256];       \
  all_output[4*bb+tx+512] = buffer[tx+512];       \
  all_output[4*bb+tx+768] = buffer[tx+768]

/* explicit coalescing, we have shuffle (at least CC3.2).
   transpose 4x4 data using __shfl(). We end up with the
   wrong block order, so recompute b, i.e indices in
   global memory:
   ##### after load (coalesced)
     thread:   0   1   2   3   4   5 ... 
   input[0]:   0   1   2   3   4   5 ...
   input[1]: 256 257 258 259 260 261 ...
   input[2]: 512 513 514 515 516 517 ...
   input[3]: 768 769 770 771 772 773 ...
   ##### after transpose
     thread:   0   1   2   3   4   5 ... 
   input[0]:   0 256 512 768   4 260 ...
   input[1]:   1 257 513 769   5 261 ...
   input[2]:   2 258 514 770   6 262 ...
   input[3]:   3 259 515 771   7 263 ...
   #####
   Coalescing only one (L or S) is probably bad for the
   other, as memory accesses will be even worse because
   of the block reordering... */
#define DEFINECOAL_coalshuf_coalshuf                     \
  uint32_t tx4x1 = (tx%4)^1;                     \
  uint32_t input[4];                             \
  uint32_t output[4];                            \
  b = bb+((tx%4)*64)+(tx>>2)
#define DEFINECOAL_coalshuf_nocoal                                  \
  uint32_t tx4x1 = (tx%4)^1;                                    \
  uint32_t input[4];                                            \
  uint32_t *output = all_output + 4*(bb+((tx%4)*64)+(tx>>2));   \
  b = bb+((tx%4)*64)+(tx>>2)
#define DEFINECOAL_nocoal_coalshuf                                  \
  uint32_t tx4x1 = (tx%4)^1;                                    \
  const uint32_t *input = all_input + 4*(bb+((tx%4)*64)+(tx>>2));     \
  uint32_t output[4];                                           \
  b = bb+((tx%4)*64)+(tx>>2)
#define INITCOAL_coalshuf                                                   \
  __syncthreads();                                                      \
  input[0] = all_input[4*bb+tx    ];                                    \
  input[1] = all_input[4*bb+tx+256];                                    \
  input[2] = all_input[4*bb+tx+512];                                    \
  input[3] = all_input[4*bb+tx+768];                                    \
  input[tx4x1  ]  = __shfl((int)input[tx4x1   ],(int)(tx^1));           \
  input[3-tx4x1]  = __shfl((int)input[3-tx4x1 ],(int)(tx^2));           \
  input[3-(tx%4)] = __shfl((int)input[3-(tx%4)],(int)(tx^3))
#define FINISHCOAL_coalshuf                           \
  output[tx4x1  ]  = __shfl((int)output[tx4x1   ],(int)(tx^1));         \
  output[3-tx4x1]  = __shfl((int)output[3-tx4x1 ],(int)(tx^2));         \
  output[3-(tx%4)] = __shfl((int)output[3-(tx%4)],(int)(tx^3));         \
  all_output[4*bb+tx    ] = output[0];                                  \
  all_output[4*bb+tx+256] = output[1];                                  \
  all_output[4*bb+tx+512] = output[2];                                  \
  all_output[4*bb+tx+768] = output[3]
  
/* parametrized function-building macro.
   fun: encrypt (ECB), ctr, gcm or gcmnoxor (gcm w/o xoring with input data - done on CPU)
   T: type of rounds
   A: number of FTs for FT-based implementation (others: 0)
   LR: type of last round
   S: size of FSb entries (8 or 32)
   COALLD: coalesce loads in shared memory (coal) or not (nocoal) or with shuffle (coalshuf)
   COALST: coalesce stores in shared memory (coal) or not (nocoal) or with shuffle (coalshuf)
   PREROUNDS: what to do before rounds
   POSTROUNDS: what to do after rounds
   -- don't mix a 'coal' and a 'coalshuf', it's not supported.
*/
#define FUNC_AES_FT(fun,T,A,LR,S,COALLD,COALST,PREROUNDS,POSTROUNDS)          \
  __global__ void aes_##fun##_cuda_##T##A##_##LR##_##S##COALLD##COALST( \
                             const uint32_t *all_input,                 \
                             uint32_t *all_output,                      \
                             const uint32_t *aes_edrk,                  \
                             const uint32_t n,                          \
                             const uint32_t* gFT0,                      \
                             const uint32_t* gFT1,                      \
                             const uint32_t* gFT2,                      \
                             const uint32_t* gFT3,                      \
                             const uint32_t* gFSb,                   \
                             const uint32_t* IV) {                      \
    const uint32_t tx = threadIdx.x;                                    \
    const uint32_t bb = ((blockIdx.x+blockIdx.y*gridDim.x)*blockDim.x); \
    /* const */ uint32_t b = bb + threadIdx.x;                                \
    DEFINECOAL_##COALLD##_##COALST;                                     \
    MAKE##A(DEFINE_SFT);                                                \
    __shared__ uint##S##_t  sFSb[256];                                  \
    __shared__ uint32_t *sFSb32;                                        \
    __shared__ uint32_t saes_edrk[64];                                  \
    TBEGIN;                                                             \
    /* assume blockDim.x == 256 */                                      \
    MAKE##A(LOAD_SFT);                                                  \
    sFSb[tx] = gFSb[tx];                                                \
    sFSb32 = (uint32_t*)sFSb;                                           \
    if (tx < 64)                                                        \
      saes_edrk[tx] = aes_edrk[tx];                                     \
                                                                        \
    INITCOAL_##COALLD;                                                    \
                                                                        \
    if (b < n) {                                                        \
                                                                        \
      uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;                          \
      unsigned int i;                                                   \
                                                                        \
      START_##fun;                                                      \
                                                                        \
      PREROUNDS(X0,X1,X2,X3)                                            \
      for (i = 4 ; i < 56 ; i+= 4) {                                    \
        AES_ROUND_CUDA_##T##A(saes_edrk, i, Y0, Y1, Y2, Y3, X0, X1, X2, X3 ); \
                                                                        \
      }                                                                 \
      POSTROUNDS(X0,X1,X2,X3)                                           \
                                                                        \
      AES_LASTROUND_CUDA_##LR(Y0,X0,X1,X2,X3);                          \
      AES_LASTROUND_CUDA_##LR(Y1,X1,X2,X3,X0);                          \
      AES_LASTROUND_CUDA_##LR(Y2,X2,X3,X0,X1);                          \
      AES_LASTROUND_CUDA_##LR(Y3,X3,X0,X1,X2);                          \
                                                                        \
      FINISH_##fun;                                                     \
    }                                                                   \
    FINISHCOAL_##COALST;                                                \
    TEND;                                                               \
  }

/* plasholder for empty pre- and post-rounds */
#define E4(A,B,C,D)


/* start building the functions... */
#define FUNC_AES_FT_ALLCOAL(fun,T,A,LR,S,PR,PO)                 \
  FUNC_AES_FT(fun,T,A,LR,S,nocoal,nocoal,PR,PO)                 \
       FUNC_AES_FT(fun,T,A,LR,S,nocoal,coal,PR,PO)              \
       FUNC_AES_FT(fun,T,A,LR,S,coal,nocoal,PR,PO)              \
       FUNC_AES_FT(fun,T,A,LR,S,coal,coal,PR,PO)                \
       FUNC_AES_FT(fun,T,A,LR,S,nocoal,coalshuf,PR,PO)          \
       FUNC_AES_FT(fun,T,A,LR,S,coalshuf,nocoal,PR,PO)          \
       FUNC_AES_FT(fun,T,A,LR,S,coalshuf,coalshuf,PR,PO)

#define FUNC_AES_ALL_FT_PP(T,A,LR,S,PR,PO)      \
  FUNC_AES_FT_ALLCOAL(encrypt,T,A,LR,S,PR,PO)   \
  FUNC_AES_FT_ALLCOAL(ctr,T,A,LR,S,PR,PO)       \
  FUNC_AES_FT_ALLCOAL(gcm,T,A,LR,S,PR,PO)       \
  FUNC_AES_FT_ALLCOAL(gcmnoxor,T,A,LR,S,PR,PO)

#define FUNC_AES_ALL_FT(T,A,LR,S)                      \
  FUNC_AES_ALL_FT_PP(T,A,LR,S,E4,E4)                   \

#include "aes_gpu_impl.h"

/* two-threads-per-block variant, ECB only ATM */
  __global__ void aes_encrypt_cuda_half(const uint32_t *all_input,
                                        uint32_t *all_output,
                                        const uint32_t *aes_edrk,
                                        const uint32_t n,
                                        const uint32_t* gFT0,
                                        const uint32_t* gFT1,
                                        const uint32_t* gFT2,
                                        const uint32_t* gFT3,
                                        const uint32_t* gFSb,
                                        const uint32_t* IV) {
  const uint32_t tx = threadIdx.x;
  const uint32_t b = (((blockIdx.x+blockIdx.y*gridDim.x)*blockDim.x) + threadIdx.x)/2;
  const uint32_t mh = threadIdx.x % 2;
  const uint32_t mo = 2*mh;
  const uint32_t *input = all_input + 4*b;
  uint32_t *output = all_output + 4*b;
  MAKE1(DEFINE_SFT);
  __shared__ uint32_t  sFSb[256];
  __shared__ uint32_t saes_edrk[64];
  /* assume blockDim.x == 256 */
  MAKE1(LOAD_SFT);
  sFSb[tx] = gFSb[tx];
  if (tx < 64)
    saes_edrk[tx] = aes_edrk[tx];
  
  __syncthreads();
  
  if (b < n) {
    uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;
    unsigned int i;
    
    X0 = input[0+mo] ^ saes_edrk[0+mo];
    X1 = input[1+mo] ^ saes_edrk[1+mo];
    X2 = __shfl_xor((int)X0, (int)0x1u);
    X3 = __shfl_xor((int)X1, (int)0x1u);
    /* even if has 0123, but odd has 2301 */


#define AES_ROUND_CUDA_FT_HALF(A,B,C,D,KEY,I,X0,X1,Y0,Y1,Y2,Y3)            \
    {                                                                   \
      X0  = LK0##A(Y0);                                                 \
      X0 ^= LK1##B(Y1);                                                 \
      X0 ^= LK2##C(Y2);                                                 \
      X0 ^= LK3##D(Y3);                                                 \
                                                                        \
      X1  = LK0##A(Y1);                                                 \
      X1 ^= LK1##B(Y2);                                                 \
      X1 ^= LK2##C(Y3);                                                 \
      X1 ^= LK3##D(Y0);                                                 \
                                                                        \
      X0 ^= (KEY[I+0+mo]);                                              \
      X1 ^= (KEY[I+1+mo]);                                              \
  }
      
    for (i = 4 ; i < 56 ; i+=4 ) {
      /* since the odd thread has the two half reversed, it's actually
         going to do what we need :-)
      */
      AES_ROUND_CUDA_FT_HALF(a,c,c,e,saes_edrk, i, Y0, Y1, X0, X1, X2, X3 );
      
      Y2 = __shfl_xor((int)Y0, (int)0x1u);
      Y3 = __shfl_xor((int)Y1, (int)0x1u);
      
      X0=Y0;
      X1=Y1;
      X2=Y2;
      X3=Y3;
    }
    i+=mo;
    AES_LASTROUND_CUDA(Y0,X0,X1,X2,X3);
    AES_LASTROUND_CUDA(Y1,X1,X2,X3,X0);
    output[0+mo] = Y0;
    output[1+mo] = Y1;
  }
}

/* four-threads-per-block variant, ECB only ATM */
__global__ void aes_encrypt_cuda_quarter(const uint32_t *all_input,
                                         uint32_t *all_output,
                                         const uint32_t *aes_edrk,
                                         const uint32_t n,
                                         const uint32_t* gFT0,
                                         const uint32_t* gFT1,
                                         const uint32_t* gFT2,
                                         const uint32_t* gFT3,
                                         const uint32_t* gFSb,
                                         const uint32_t* IV) {
  const uint32_t tx = threadIdx.x;
  const uint32_t b = (((blockIdx.x+blockIdx.y*gridDim.x)*blockDim.x) + threadIdx.x)/4;
  const uint32_t mh = threadIdx.x % 4;
  const uint32_t bt = threadIdx.x & ~3;
  const uint32_t *input = all_input + 4*b;
  uint32_t *output = all_output + 4*b;
  MAKE1(DEFINE_SFT);
  __shared__ uint32_t  sFSb[256];
  __shared__ uint32_t saes_edrk[64];
  /* assume blockDim.x == 256 */
  MAKE1(LOAD_SFT);
  sFSb[tx] = gFSb[tx];
  if (tx < 64)
    saes_edrk[tx] = aes_edrk[tx];
  
  __syncthreads();
  
  if (b < n) {
    uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;
    unsigned int i;
    
    /* access to input is perfectly aligned & coalesced */
    X0 = input[0+mh] ^ saes_edrk[0+mh];
    X1 = __shfl((int)X0, (int)(bt+((mh+1)%4)));
    X2 = __shfl((int)X0, (int)(bt+((mh+2)%4)));
    X3 = __shfl((int)X0, (int)(bt+((mh+3)%4)));

#define AES_ROUND_CUDA_FT_QUARTER(A,B,C,D,KEY,I,X0,Y0,Y1,Y2,Y3)            \
    {                                                                   \
      X0  = LK0##A(Y0);                                                 \
      X0 ^= LK1##B(Y1);                                                 \
      X0 ^= LK2##C(Y2);                                                 \
      X0 ^= LK3##D(Y3);                                                 \
                                                                        \
      X0 ^= (KEY[I+mh]);                                                \
  }
      
    for (i = 4 ; i < 56 ; i+=4 ) {
      AES_ROUND_CUDA_FT_QUARTER(a,c,c,e,saes_edrk, i, Y0, X0, X1, X2, X3 );
      Y1 = __shfl((int)Y0, (int)(bt+((mh+1)%4)));
      Y2 = __shfl((int)Y0, (int)(bt+((mh+2)%4)));
      Y3 = __shfl((int)Y0, (int)(bt+((mh+3)%4)));
      
      X0=Y0;
      X1=Y1;
      X2=Y2;
      X3=Y3;
    }
    i+=mh;
    AES_LASTROUND_CUDA(Y0,X0,X1,X2,X3);
    output[0+mh] = Y0;
  }
}

#endif
