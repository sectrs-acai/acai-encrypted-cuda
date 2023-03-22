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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "aes_common.h"
#include "aes_gcm.h"


typedef void (*addmul_proto)(unsigned char *, const unsigned char *, const unsigned long long, const unsigned char *);
typedef void (*addmul_start_proto)(const unsigned char *, const unsigned char *);
typedef void (*addmul_finish_proto)(unsigned char *);

/* reference addmul for GCM;
   this is from the supercop benchmark <http://bench.cr.yp.to/supercop.html>
   directory "supercop-$VERSION/crypto_aead/aes256gcmv1/ref"
*/
void addmul_ref(unsigned char *a,
                const unsigned char *x,
                const unsigned long long xlen,
                const unsigned char *y)
{
  int i;
  int j;
  unsigned char abits[128];
  unsigned char ybits[128];
  unsigned char prodbits[256];
  for (i = 0;i < xlen;++i) a[i] ^= x[i];
  for (i = 0;i < 128;++i) abits[i] = (a[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0;i < 128;++i) ybits[i] = (y[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0;i < 256;++i) prodbits[i] = 0;
  for (i = 0;i < 128;++i)
    for (j = 0;j < 128;++j)
      prodbits[i + j] ^= abits[i] & ybits[j];
  for (i = 127;i >= 0;--i) {
    prodbits[i] ^= prodbits[i + 128];
    prodbits[i + 1] ^= prodbits[i + 128];
    prodbits[i + 2] ^= prodbits[i + 128];
    prodbits[i + 7] ^= prodbits[i + 128];
    prodbits[i + 128] ^= prodbits[i + 128];
  }
  for (i = 0;i < 16;++i) a[i] = 0;
  for (i = 0;i < 128;++i) a[i / 8] |= (prodbits[i] << (7 - (i % 8)));
}
void addmul_start_ref(const unsigned char *c, const unsigned char *H) {
  /* nothing */
}
void addmul_finish_ref(unsigned char *c) {
  /* nothing */
}

//#if defined(__x86_64__)
//void addmul(unsigned char *a,
//            const unsigned char *x,
//            const unsigned long long xlen,
//            const unsigned char *y) {
//  // TODO
//}
//#endif
#if defined(__PCLMUL__)
#include <immintrin.h>
/* This GF(2^128) function is by the book, meaning this one:
   <https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf>
   this if from supercop/aes256gcmv1/dolbeau/aesenc-int/
   one could instead use the even faster reduce4 or reduce8 from the same source.
*/
void addmul_pclmul(unsigned char *c,
                   const unsigned char *a, 
	           const unsigned long long xlen,
                   const unsigned char *b) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  const __m128i ff = _mm_set1_epi32(0xFFFFFFFF);
  __m128i A = _mm_loadu_si128((const __m128i*)a);
  A = _mm_shuffle_epi8(A, rev);
  if (xlen < 16) { // less than 16 useful bytes - insert zeroes where needed
    unsigned long long mask = -1ull ^ (1ull<<(((16-xlen)%8)*8))-1ull;
    __m128i vm;
    if (xlen>8) {
      vm = _mm_insert_epi64(ff, mask, 0);
    } else {
      vm = _mm_insert_epi64(_mm_setzero_si128(),mask,1);
    }
    A = _mm_and_si128(vm, A);
  }
  __m128i B = _mm_loadu_si128((const __m128i*)b);
  B = _mm_shuffle_epi8(B, rev);
  __m128i C = _mm_loadu_si128((const __m128i*)c);
  C = _mm_shuffle_epi8(C, rev);
  A = _mm_xor_si128(A,C);
  __m128i tmp3 = _mm_clmulepi64_si128(A, B, 0x00);
  __m128i tmp4 = _mm_clmulepi64_si128(A, B, 0x10);
  __m128i tmp5 = _mm_clmulepi64_si128(A, B, 0x01);
  __m128i tmp6 = _mm_clmulepi64_si128(A, B, 0x11);
  __m128i tmp10 = _mm_xor_si128(tmp4, tmp5);
  __m128i tmp13 = _mm_slli_si128(tmp10, 8);
  __m128i tmp11 = _mm_srli_si128(tmp10, 8);
  __m128i tmp15 = _mm_xor_si128(tmp3, tmp13);
  __m128i tmp17 = _mm_xor_si128(tmp6, tmp11);
  __m128i tmp7 = _mm_srli_epi32(tmp15, 31);
  __m128i tmp8 = _mm_srli_epi32(tmp17, 31);
  __m128i tmp16 = _mm_slli_epi32(tmp15, 1);
  __m128i tmp18 = _mm_slli_epi32(tmp17, 1);
  __m128i tmp9 = _mm_srli_si128(tmp7, 12);
  __m128i tmp22 = _mm_slli_si128(tmp8, 4);
  __m128i tmp25 = _mm_slli_si128(tmp7, 4);
  __m128i tmp29 =_mm_or_si128(tmp16, tmp25);
  __m128i tmp19 = _mm_or_si128(tmp18, tmp22);
  __m128i tmp20 = _mm_or_si128(tmp19, tmp9);
  __m128i tmp26 = _mm_slli_epi32(tmp29, 31);
  __m128i tmp23 = _mm_slli_epi32(tmp29, 30);
  __m128i tmp32 = _mm_slli_epi32(tmp29, 25);
  __m128i tmp27 = _mm_xor_si128(tmp26, tmp23);
  __m128i tmp28 = _mm_xor_si128(tmp27, tmp32);
  __m128i tmp24 = _mm_srli_si128(tmp28, 4);
  __m128i tmp33 = _mm_slli_si128(tmp28, 12);
  __m128i tmp30 = _mm_xor_si128(tmp29, tmp33);
  __m128i tmp2 = _mm_srli_epi32(tmp30, 1);
  __m128i tmp12 = _mm_srli_epi32(tmp30, 2);
  __m128i tmp14 = _mm_srli_epi32(tmp30, 7);
  __m128i tmp34 = _mm_xor_si128(tmp2, tmp12);
  __m128i tmp35 = _mm_xor_si128(tmp34, tmp14);
  __m128i tmp36 = _mm_xor_si128(tmp35, tmp24);
  __m128i tmp31 = _mm_xor_si128(tmp30, tmp36);
  __m128i tmp21 = _mm_xor_si128(tmp20, tmp31);
  tmp21 = _mm_shuffle_epi8(tmp21, rev);
  _mm_storeu_si128((__m128i*)c, tmp21);
}
void addmul_start_pclmul(const unsigned char *c, const unsigned char *H) {
  /* nothing */
}
void addmul_finish_pclmul(unsigned char *c) {
  /* nothing */
}

/* all the MAKE* macros are for automatic explicit unrolling */
#define MAKE2(X)                                \
  X(0);X(1)

#define MAKE4(X)                                \
  X(0);X(1);X(2);X(3)

#define MAKE6(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5)

#define MAKE7(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6)

#define MAKE8(X)                                \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7)

#define MAKE10(X)                               \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7);                          \
  X(8);X(9)

#define MAKE12(X)                               \
  X(0);X(1);X(2);X(3);                          \
  X(4);X(5);X(6);X(7);                          \
  X(8);X(9);X(10);X(11)

/* pure multiplication, for pre-computing  powers of H */
static inline __m128i mulv(__m128i A,
                           __m128i B) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i tmp3 = _mm_clmulepi64_si128(A, B, 0x00);
  __m128i tmp4 = _mm_clmulepi64_si128(A, B, 0x10);
  __m128i tmp5 = _mm_clmulepi64_si128(A, B, 0x01);
  __m128i tmp6 = _mm_clmulepi64_si128(A, B, 0x11);
  __m128i tmp10 = _mm_xor_si128(tmp4, tmp5);
  __m128i tmp13 = _mm_slli_si128(tmp10, 8);
  __m128i tmp11 = _mm_srli_si128(tmp10, 8);
  __m128i tmp15 = _mm_xor_si128(tmp3, tmp13);
  __m128i tmp17 = _mm_xor_si128(tmp6, tmp11);
  __m128i tmp7 = _mm_srli_epi32(tmp15, 31);
  __m128i tmp8 = _mm_srli_epi32(tmp17, 31);
  __m128i tmp16 = _mm_slli_epi32(tmp15, 1);
  __m128i tmp18 = _mm_slli_epi32(tmp17, 1);
  __m128i tmp9 = _mm_srli_si128(tmp7, 12);
  __m128i tmp22 = _mm_slli_si128(tmp8, 4);
  __m128i tmp25 = _mm_slli_si128(tmp7, 4);
  __m128i tmp29 =_mm_or_si128(tmp16, tmp25);
  __m128i tmp19 = _mm_or_si128(tmp18, tmp22);
  __m128i tmp20 = _mm_or_si128(tmp19, tmp9);
  __m128i tmp26 = _mm_slli_epi32(tmp29, 31);
  __m128i tmp23 = _mm_slli_epi32(tmp29, 30);
  __m128i tmp32 = _mm_slli_epi32(tmp29, 25);
  __m128i tmp27 = _mm_xor_si128(tmp26, tmp23);
  __m128i tmp28 = _mm_xor_si128(tmp27, tmp32);
  __m128i tmp24 = _mm_srli_si128(tmp28, 4);
  __m128i tmp33 = _mm_slli_si128(tmp28, 12);
  __m128i tmp30 = _mm_xor_si128(tmp29, tmp33);
  __m128i tmp2 = _mm_srli_epi32(tmp30, 1);
  __m128i tmp12 = _mm_srli_epi32(tmp30, 2);
  __m128i tmp14 = _mm_srli_epi32(tmp30, 7);
  __m128i tmp34 = _mm_xor_si128(tmp2, tmp12);
  __m128i tmp35 = _mm_xor_si128(tmp34, tmp14);
  __m128i tmp36 = _mm_xor_si128(tmp35, tmp24);
  __m128i tmp31 = _mm_xor_si128(tmp30, tmp36);
  __m128i C = _mm_xor_si128(tmp20, tmp31);
  return C;
}

static inline __m128i reduce4(__m128i H0, __m128i H1, __m128i H2, __m128i H3,
                              __m128i X0, __m128i X1, __m128i X2, __m128i X3, __m128i acc)
{
  /*algorithm by Krzysztof Jankowski, Pierre Laurent - Intel*/
#define RED_DECL(a) __m128i H##a##_X##a##_lo, H##a##_X##a##_hi, tmp##a, tmp##a##B
  MAKE4(RED_DECL);
  __m128i lo, tmplo, hi, tmphi;
  __m128i tmp8, tmp9;
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  /* byte-revert the inputs & xor the first one into the accumulator */
#define RED_SHUFFLE(a) X##a = _mm_shuffle_epi8(X##a, rev)
  MAKE4(RED_SHUFFLE);
  X3 = _mm_xor_si128(X3,acc);

  /* 4 low H*X (x0*h0) */
#define RED_MUL_LOW(a) H##a##_X##a##_lo = _mm_clmulepi64_si128(H##a, X##a, 0x00)
  MAKE4(RED_MUL_LOW);
  lo = _mm_xor_si128(H0_X0_lo, H1_X1_lo);
  lo = _mm_xor_si128(lo, H2_X2_lo);
  lo = _mm_xor_si128(lo, H3_X3_lo);

  /* 4 high H*X (x1*h1) */
#define RED_MUL_HIGH(a) H##a##_X##a##_hi = _mm_clmulepi64_si128(H##a, X##a, 0x11)
  MAKE4(RED_MUL_HIGH);
  hi = _mm_xor_si128(H0_X0_hi, H1_X1_hi);
  hi = _mm_xor_si128(hi, H2_X2_hi);
  hi = _mm_xor_si128(hi, H3_X3_hi);

  /* 4 middle H*X, using Karatsuba, i.e.
     x1*h0+x0*h1 =(x1+x0)*(h1+h0)-x1*h1-x0*h0
     we already have all x1y1 & x0y0 (accumulated in hi & lo)
     (0 is low half and 1 is high half)
  */
  /* permute the high and low 64 bits in H1 & X1,
     so create (h0,h1) from (h1,h0) and (x0,x1) from (x1,x0),
     then compute (h0+h1,h1+h0) and (x0+x1,x1+x0),
     and finally multiply
  */
#define RED_MUL_MID(a)                                \
  tmp##a    = _mm_shuffle_epi32(H##a, 0x4e);          \
  tmp##a##B = _mm_shuffle_epi32(X##a, 0x4e);          \
  tmp##a    = _mm_xor_si128(tmp##a, H##a);            \
  tmp##a##B = _mm_xor_si128(tmp##a##B, X##a);         \
  tmp##a    = _mm_clmulepi64_si128(tmp##a, tmp##a##B, 0x00)
  MAKE4(RED_MUL_MID);

  /* substracts x1*h1 and x0*h0 */
#if 1
  tmp0 = _mm_xor_si128(tmp0, lo);
  tmp0 = _mm_xor_si128(tmp0, hi);
  tmp0 = _mm_xor_si128(tmp1, tmp0);
  tmp0 = _mm_xor_si128(tmp2, tmp0);
  tmp0 = _mm_xor_si128(tmp3, tmp0);
#else
  tmp0 = _mm_xor_si128(tmp0, lo);
  tmp1 = _mm_xor_si128(tmp1, hi);
  tmp2 = _mm_xor_si128(tmp2, tmp3);
  tmp1 = _mm_xor_si128(tmp0, tmp1);
  tmp0 = _mm_xor_si128(tmp1,tmp2);
#endif

  /* reduction */
  tmp0B = _mm_slli_si128(tmp0, 8);
  tmp0  = _mm_srli_si128(tmp0, 8);
  lo    = _mm_xor_si128(tmp0B, lo);
  hi    = _mm_xor_si128(tmp0, hi);
  tmp3  = lo;
  tmp2B = hi;
  tmp3B = _mm_srli_epi32(tmp3, 31);
  tmp8  = _mm_srli_epi32(tmp2B, 31);
  tmp3  = _mm_slli_epi32(tmp3, 1);
  tmp2B = _mm_slli_epi32(tmp2B, 1);
  tmp9  = _mm_srli_si128(tmp3B, 12);
  tmp8  = _mm_slli_si128(tmp8, 4);
  tmp3B = _mm_slli_si128(tmp3B, 4);
  tmp3  = _mm_or_si128(tmp3, tmp3B);
  tmp2B = _mm_or_si128(tmp2B, tmp8);
  tmp2B = _mm_or_si128(tmp2B, tmp9);
  tmp3B = _mm_slli_epi32(tmp3, 31);
  tmp8  = _mm_slli_epi32(tmp3, 30);
  tmp9  = _mm_slli_epi32(tmp3, 25);
  tmp3B = _mm_xor_si128(tmp3B, tmp8);
  tmp3B = _mm_xor_si128(tmp3B, tmp9);
  tmp8  = _mm_srli_si128(tmp3B, 4);
  tmp3B = _mm_slli_si128(tmp3B, 12);
  tmp3  = _mm_xor_si128(tmp3, tmp3B);
  tmp2  = _mm_srli_epi32(tmp3, 1);
  tmp0B = _mm_srli_epi32(tmp3, 2);
  tmp1B = _mm_srli_epi32(tmp3, 7);
  tmp2  = _mm_xor_si128(tmp2, tmp0B);
  tmp2  = _mm_xor_si128(tmp2, tmp1B);
  tmp2  = _mm_xor_si128(tmp2, tmp8);
  tmp3  = _mm_xor_si128(tmp3, tmp2);
  tmp2B = _mm_xor_si128(tmp2B, tmp3);
  return tmp2B;
}
static inline __m128i reduce8(__m128i H0, __m128i H1, __m128i H2, __m128i H3,
                              __m128i H4, __m128i H5, __m128i H6, __m128i H7,
                              __m128i X0, __m128i X1, __m128i X2, __m128i X3,
                              __m128i X4, __m128i X5, __m128i X6, __m128i X7, __m128i acc)
{
  /*algorithm by Krzysztof Jankowski, Pierre Laurent - Intel*/
  MAKE8(RED_DECL);
  __m128i lo, tmplo, hi, tmphi;
  __m128i tmp8, tmp9;
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  /* byte-revert the inputs & xor the first one into the accumulator */
  MAKE8(RED_SHUFFLE);
  X7 = _mm_xor_si128(X7,acc);

  /* 8 low H*X (x0*h0) */
  MAKE8(RED_MUL_LOW);
  lo = _mm_xor_si128(H0_X0_lo, H1_X1_lo);
  lo = _mm_xor_si128(lo, H2_X2_lo);
  lo = _mm_xor_si128(lo, H3_X3_lo);
  lo = _mm_xor_si128(lo, H4_X4_lo);
  lo = _mm_xor_si128(lo, H5_X5_lo);
  lo = _mm_xor_si128(lo, H6_X6_lo);
  lo = _mm_xor_si128(lo, H7_X7_lo);

  /* 8 high H*X (x1*h1) */
#define RED_MUL_HIGH(a) H##a##_X##a##_hi = _mm_clmulepi64_si128(H##a, X##a, 0x11)
  MAKE8(RED_MUL_HIGH);
  hi = _mm_xor_si128(H0_X0_hi, H1_X1_hi);
  hi = _mm_xor_si128(hi, H2_X2_hi);
  hi = _mm_xor_si128(hi, H3_X3_hi);
  hi = _mm_xor_si128(hi, H4_X4_hi);
  hi = _mm_xor_si128(hi, H5_X5_hi);
  hi = _mm_xor_si128(hi, H6_X6_hi);
  hi = _mm_xor_si128(hi, H7_X7_hi);

  /* 8 middle H*X, using Karatsuba, i.e.
     x1*h0+x0*h1 =(x1+x0)*(h1+h0)-x1*h1-x0*h0
     we already have all x1y1 & x0y0 (accumulated in hi & lo)
     (0 is low half and 1 is high half)
  */
  /* permute the high and low 64 bits in H1 & X1,
     so create (h0,h1) from (h1,h0) and (x0,x1) from (x1,x0),
     then compute (h0+h1,h1+h0) and (x0+x1,x1+x0),
     and finally multiply
  */
#define RED_MUL_MID(a)                                \
  tmp##a    = _mm_shuffle_epi32(H##a, 0x4e);          \
  tmp##a##B = _mm_shuffle_epi32(X##a, 0x4e);          \
  tmp##a    = _mm_xor_si128(tmp##a, H##a);            \
  tmp##a##B = _mm_xor_si128(tmp##a##B, X##a);         \
  tmp##a    = _mm_clmulepi64_si128(tmp##a, tmp##a##B, 0x00)
  MAKE8(RED_MUL_MID);

  /* substracts x1*h1 and x0*h0 */
  tmp0 = _mm_xor_si128(tmp0, lo);
  tmp0 = _mm_xor_si128(tmp0, hi);
  tmp0 = _mm_xor_si128(tmp1, tmp0);
  tmp0 = _mm_xor_si128(tmp2, tmp0);
  tmp0 = _mm_xor_si128(tmp3, tmp0);
  tmp0 = _mm_xor_si128(tmp4, tmp0);
  tmp0 = _mm_xor_si128(tmp5, tmp0);
  tmp0 = _mm_xor_si128(tmp6, tmp0);
  tmp0 = _mm_xor_si128(tmp7, tmp0);

  /* reduction */
  tmp0B = _mm_slli_si128(tmp0, 8);
  tmp0  = _mm_srli_si128(tmp0, 8);
  lo    = _mm_xor_si128(tmp0B, lo);
  hi    = _mm_xor_si128(tmp0, hi);
  tmp3  = lo;
  tmp2B = hi;
  tmp3B = _mm_srli_epi32(tmp3, 31);
  tmp8  = _mm_srli_epi32(tmp2B, 31);
  tmp3  = _mm_slli_epi32(tmp3, 1);
  tmp2B = _mm_slli_epi32(tmp2B, 1);
  tmp9  = _mm_srli_si128(tmp3B, 12);
  tmp8  = _mm_slli_si128(tmp8, 4);
  tmp3B = _mm_slli_si128(tmp3B, 4);
  tmp3  = _mm_or_si128(tmp3, tmp3B);
  tmp2B = _mm_or_si128(tmp2B, tmp8);
  tmp2B = _mm_or_si128(tmp2B, tmp9);
  tmp3B = _mm_slli_epi32(tmp3, 31);
  tmp8  = _mm_slli_epi32(tmp3, 30);
  tmp9  = _mm_slli_epi32(tmp3, 25);
  tmp3B = _mm_xor_si128(tmp3B, tmp8);
  tmp3B = _mm_xor_si128(tmp3B, tmp9);
  tmp8  = _mm_srli_si128(tmp3B, 4);
  tmp3B = _mm_slli_si128(tmp3B, 12);
  tmp3  = _mm_xor_si128(tmp3, tmp3B);
  tmp2  = _mm_srli_epi32(tmp3, 1);
  tmp0B = _mm_srli_epi32(tmp3, 2);
  tmp1B = _mm_srli_epi32(tmp3, 7);
  tmp2  = _mm_xor_si128(tmp2, tmp0B);
  tmp2  = _mm_xor_si128(tmp2, tmp1B);
  tmp2  = _mm_xor_si128(tmp2, tmp8);
  tmp3  = _mm_xor_si128(tmp3, tmp2);
  tmp2B = _mm_xor_si128(tmp2B, tmp3);
  return tmp2B;
}

void compute_4power_pclmul(const unsigned char* H,
                           unsigned char* Hn) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i Hv = _mm_loadu_si128(H);
  Hv = _mm_shuffle_epi8(Hv, rev);
  __m128i H2v = mulv(Hv, Hv);
  __m128i H3v = mulv(H2v, Hv);
  __m128i H4v = mulv(H3v, Hv);
  _mm_storeu_si128(Hn +  0, Hv);
  _mm_storeu_si128(Hn + 16, H2v);
  _mm_storeu_si128(Hn + 32, H3v);
  _mm_storeu_si128(Hn + 48, H4v);
}

void compute_8power_pclmul(const unsigned char* H,
                           unsigned char* Hn) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i Hv = _mm_loadu_si128(H);
  Hv = _mm_shuffle_epi8(Hv, rev);
  __m128i H2v = mulv(Hv, Hv);
  __m128i H3v = mulv(H2v, Hv);
  __m128i H4v = mulv(H3v, Hv);
  __m128i H5v = mulv(H4v, Hv);
  __m128i H6v = mulv(H5v, Hv);
  __m128i H7v = mulv(H6v, Hv);
  __m128i H8v = mulv(H7v, Hv);
  _mm_storeu_si128(Hn +  0, Hv);
  _mm_storeu_si128(Hn + 16, H2v);
  _mm_storeu_si128(Hn + 32, H3v);
  _mm_storeu_si128(Hn + 48, H4v);
  _mm_storeu_si128(Hn + 64, H5v);
  _mm_storeu_si128(Hn + 80, H6v);
  _mm_storeu_si128(Hn + 96, H7v);
  _mm_storeu_si128(Hn +112, H8v);
}

void addmul8_pclmul(unsigned char *c,
                    const unsigned char *a, 
                    const unsigned char *bn) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i Hv  = _mm_loadu_si128(bn +  0);
  __m128i H2v = _mm_loadu_si128(bn + 16);
  __m128i H3v = _mm_loadu_si128(bn + 32);
  __m128i H4v = _mm_loadu_si128(bn + 48);
  __m128i H5v = _mm_loadu_si128(bn + 64);
  __m128i H6v = _mm_loadu_si128(bn + 80);
  __m128i H7v = _mm_loadu_si128(bn + 96);
  __m128i H8v = _mm_loadu_si128(bn +112);
  __m128i accv = _mm_loadu_si128(c);
  __m128i X0 = _mm_loadu_si128(a +  0);
  __m128i X1 = _mm_loadu_si128(a + 16);
  __m128i X2 = _mm_loadu_si128(a + 32);
  __m128i X3 = _mm_loadu_si128(a + 48);
  __m128i X4 = _mm_loadu_si128(a + 64);
  __m128i X5 = _mm_loadu_si128(a + 80);
  __m128i X6 = _mm_loadu_si128(a + 96);
  __m128i X7 = _mm_loadu_si128(a +112);
  accv = _mm_shuffle_epi8(accv, rev);
  accv = reduce8(Hv,H2v,H3v,H4v,H5v,H6v,H7v,H8v,
                 X7, X6, X5, X4, X3, X2, X1, X0,
                 accv);
  accv = _mm_shuffle_epi8(accv, rev);
  _mm_storeu_si128(c, accv);
}

void addmul4_pclmul(unsigned char *c,
                    const unsigned char *a, 
                    const unsigned char *bn) {
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i Hv  = _mm_loadu_si128(bn +  0);
  __m128i H2v = _mm_loadu_si128(bn + 16);
  __m128i H3v = _mm_loadu_si128(bn + 32);
  __m128i H4v = _mm_loadu_si128(bn + 48);
  __m128i accv = _mm_loadu_si128(c);
  __m128i X0 = _mm_loadu_si128(a +  0);
  __m128i X1 = _mm_loadu_si128(a + 16);
  __m128i X2 = _mm_loadu_si128(a + 32);
  __m128i X3 = _mm_loadu_si128(a + 48);
  accv = _mm_shuffle_epi8(accv, rev);
  accv = reduce4(Hv,H2v,H3v,H4v,
                 X3, X2, X1, X0,
                 accv);
  accv = _mm_shuffle_epi8(accv, rev);
  _mm_storeu_si128(c, accv);
}

#endif

#if defined(__arm__) || defined(__aarch64__)
#include <arm_neon.h>

/* 64x64 -> 128 multiplication for GCM.
   This is a straightforward implementation of the algorithm
   & ASM sample code from
   "Fast Software Polynomial Multiplication on
   ARM Processors using the NEON Engine" by Camara et al.
   <http://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf>
   This is replaced by "vmull.p64" in AArch64.
*/ 
static inline  poly16x8_t mul64neon(const poly8x8_t ad,
                                    const poly8x8_t bd) {
  /* helper */
#define vext_p8(a,b,c) vreinterpret_p8_u8(vext_u8(vreinterpret_u8_p8(a),vreinterpret_u8_p8(b),c))
#define vextq_p16(a,b,c) vreinterpretq_p16_u16(vextq_u16(vreinterpretq_u16_p16(a),vreinterpretq_u16_p16(b),c))
#define veor_p8(a,b) vreinterpret_p8_u8(veor_u8(vreinterpret_u8_p8(a),vreinterpret_u8_p8(b)))
#define vand_p8(a,b) vreinterpret_p8_u8(vand_u8(vreinterpret_u8_p8(a),vreinterpret_u8_p8(b)))
#define veorq_p16(a,b) vreinterpretq_p16_u16(veorq_u16(vreinterpretq_u16_p16(a), vreinterpretq_u16_p16(b)))
#define vextq_p8a(a,b,c) vreinterpretq_p16_p8(vextq_p8(vreinterpretq_p8_p16(a),vreinterpretq_p8_p16(b),c))


  poly16x8_t rq,t0q,t1q,t2q,t3q;
  poly8x8_t rl, rh;
  poly8x8_t t0l,t0h;
  poly8x8_t t1l,t1h;
  poly8x8_t t2l,t2h;
  poly8x8_t t3l,t3h;
  poly8x8_t k16 = vcreate_p8(0x000000000000FFFFULL);
  poly8x8_t k32 = vcreate_p8(0x00000000FFFFFFFFULL);
  poly8x8_t k48 = vcreate_p8(0x0000FFFFFFFFFFFFULL);

  t0l = vext_p8(ad,ad,1);
  t0q = vmull_p8(t0l,bd);
  rl  = vext_p8(bd,bd,1);
  rq  = vmull_p8(ad,rl);
  
  t1l = vext_p8(ad,ad,2);
  t1q = vmull_p8(t1l,bd);
  t3l = vext_p8(bd,bd,2);
  t3q = vmull_p8(ad,t3l);
  
  t2l = vext_p8(ad,ad,3);
  t2q = vmull_p8(t2l,bd);
  t0q = veorq_p16(t0q, rq);
  rl  = vext_p8(bd,bd,3);
  rq  = vmull_p8(ad,rl);
  
  t1q = veorq_p16(t1q,t3q);
  t3l = vext_p8(bd,bd,4);
  t3q = vmull_p8(ad,t3l);

t0l = vget_low_p8(vreinterpretq_p8_p16(t0q));
t0h = vget_high_p8(vreinterpretq_p8_p16(t0q));
  t0l = veor_p8(t0l,t0h);
  t0h = vand_p8(t0h,k48);
t1l = vget_low_p8(vreinterpretq_p8_p16(t1q));
t1h = vget_high_p8(vreinterpretq_p8_p16(t1q));
  t1l = veor_p8(t1l,t1h);
  t1h = vand_p8(t1h,k32);

  t2q = veorq_p16(t2q,rq);
  t0l = veor_p8(t0l,t0h);
  t1l = veor_p8(t1l,t1h);
t2l = vget_low_p8(vreinterpretq_p8_p16(t2q));
t2h = vget_high_p8(vreinterpretq_p8_p16(t2q));
  t2l = veor_p8(t2l,t2h);
  t2h = vand_p8(t2h,k16);
t3l = vget_low_p8(vreinterpretq_p8_p16(t3q));
t3h = vget_high_p8(vreinterpretq_p8_p16(t3q));
  t3l = veor_p8(t3l,t3h);
  t3h = vcreate_p8(0);
  
t0q = vreinterpretq_p16_p8(vcombine_p8(t0l,t0h));
  t0q = vextq_p8a(t0q,t0q,15);
  t2l = veor_p8(t2l,t2h);
t1q = vreinterpretq_p16_p8(vcombine_p8(t1l,t1h));
  t1q = vextq_p8a(t1q,t1q,14);

  rq = vmull_p8(ad,bd);
t2q = vreinterpretq_p16_p8(vcombine_p8(t2l,t2h));
  t2q = vextq_p8a(t2q,t2q,13);
t3q = vreinterpretq_p16_p8(vcombine_p8(t3l,t3h));
  t3q = vextq_p8a(t3q,t3q,12);
  
  t0q = veorq_p16(t0q,t1q);
  t2q = veorq_p16(t2q,t3q);
  rq = veorq_p16(rq,t0q);
  rq = veorq_p16(rq,t2q);

  return rq;
}

#define printp8x8(name, data) do {                   \
    int i;                                           \
    static uint8_t p[8];                             \
    vst1_p8((poly8_t*)p, data);                    \
    printf (""#name" "#data": ");                    \
    for (i = 0; i < 2; i++) {                        \
      printf ("0x%08x ", ((uint32_t*)p)[i]);         \
    }                                                \
    printf ("\n");                                   \
  } while(0)
#define printp16x8(name, data) do {                \
    int i;                                         \
    static uint8_t p[16];                          \
    vst1q_p16((poly16_t*)p, data);               \
    printf (""#name" "#data": ");                  \
    for (i = 0; i < 4; i++) {                     \
      printf ("0x%08x ", ((uint32_t*)p)[i]);       \
    }                                              \
    printf ("\n");                                 \
  } while(0)

/* ARM bit-reversal inside a 32 bits word */
static inline uint32_t rbit(const uint32_t x) {
  uint32_t r= 0xDEADBEEF;
  asm("rbit %0,%1" : "=r"(r) : "r"(x));
  return r;
}

/* ARM byte-reversal inside a 32 bits word */
static inline uint32_t bswap32(const uint32_t x) {
#if 0
  uint32_t t = 0;
  t |= (((x >>  0)&0xFF) << 24);
  t |= (((x >>  8)&0xFF) << 16);
  t |= (((x >> 16)&0xFF) <<  8);
  t |= (((x >> 24)&0xFF) <<  0);
  return t;
#else
  uint32_t r;
  asm("rev %0,%1" : "=r"(r) : "r"(x));
  return r;
#endif
}

/* 128x128 GCM.
   calling the Camara et al. multiplier above,
   and the Karatsuba multiplication. Plus reduction.
   Beware: doesn't bit-reverse.
*/
static inline  void addmul_neon_nobr(unsigned char *a,
                                   const unsigned char *x,
                                   const unsigned long long xlen,
                                   const unsigned char *y) {
  poly8x8_t adl = vld1_p8((const poly8_t*)(a  ));
  poly8x8_t xdl = vld1_p8((const poly8_t*)(x  ));
  poly8x8_t ydl = vld1_p8((const poly8_t*)(y  ));
  poly8x8_t adh = vld1_p8((const poly8_t*)(a+8));
  poly8x8_t xdh = vld1_p8((const poly8_t*)(x+8));
  poly8x8_t ydh = vld1_p8((const poly8_t*)(y+8));
  adl = veor_p8(adl,xdl);
  adh = veor_p8(adh,xdh);
  /* 3 calls to mul64neon for Karatsuba multiplication 128x128 */
#if defined(__aarch64__)
/*   poly16x8_t rql = vreinterpretq_p16_p128(vmull_p64(vreinterpret_p64_p8(adl),vreinterpret_p64_p8(ydl))); */
/*   poly16x8_t rqh = vreinterpretq_p16_p128(vmull_p64(vreinterpret_p64_p8(adh),vreinterpret_p64_p8(ydh))); */
  poly16x8_t rql = (poly16x8_t)(vmull_p64((poly64_t)(adl),(poly64_t)(ydl)));
  poly16x8_t rqh = (poly16x8_t)(vmull_p64((poly64_t)(adh),(poly64_t)(ydh)));
#else
  poly16x8_t rql = mul64neon(adl,ydl);
  poly16x8_t rqh = mul64neon(adh,ydh);
#endif
/* poly16x8_t rqlh = mul64neon(adl,ydh); */
/* printp16x8(a,rqlh); */
/* poly16x8_t rqhl = mul64neon(adh,ydl); */
/* printp16x8(a,rqhl); */
  poly8x8_t ydhxl = veor_p8(ydl,ydh);
  poly8x8_t adhxl = veor_p8(adl,adh);
#if defined(__aarch64__)
/*   poly16x8_t rqm = vreinterpretq_p16_p128(vmull_p64(vreinterpret_p64_p8(adhxl),vreinterpret_p64_p8(ydhxl))); */
  poly16x8_t rqm = (poly16x8_t)(vmull_p64((poly64_t)(adhxl),(poly64_t)(ydhxl)));
#else
  poly16x8_t rqm = mul64neon(adhxl,ydhxl);
#endif
  poly16x8_t rqlxm = veorq_p16(rql,rqm);
  poly16x8_t rqlxmxh = veorq_p16(rqlxm,rqh);
  poly8x8_t rd0 = vget_low_p8(vreinterpretq_p8_p16(rql));
  poly8x8_t rd1 = vget_high_p8(vreinterpretq_p8_p16(rql));
  poly8x8_t rd1m = vget_low_p8(vreinterpretq_p8_p16(rqlxmxh));
  poly8x8_t rd2m = vget_high_p8(vreinterpretq_p8_p16(rqlxmxh));
  poly8x8_t rd2 = vget_low_p8(vreinterpretq_p8_p16(rqh));
  poly8x8_t rd3 = vget_high_p8(vreinterpretq_p8_p16(rqh));
  poly8x8_t rd1c = veor_p8(rd1,rd1m);
  poly8x8_t rd2c = veor_p8(rd2,rd2m);
  rql = vreinterpretq_p16_p8(vcombine_p8(rd0,rd1c));
  //rqh = vreinterpretq_p16_p8(vcombine_p8(rd2c,rd3));
  poly8x8_t k135 = vcreate_p8(0x8787878787878787ULL);
  poly16x8_t pq2 = vmull_p8(rd2c,k135);
  poly16x8_t pq3 = vmull_p8(rd3,k135);
  poly8x8x2_t uq4 = vuzp_p8(vget_low_p8(vreinterpretq_p8_p16(pq2)),vget_high_p8(vreinterpretq_p8_p16(pq2)));
  poly8x8x2_t uq6 = vuzp_p8(vget_low_p8(vreinterpretq_p8_p16(pq3)),vget_high_p8(vreinterpretq_p8_p16(pq3)));
  poly16x8_t rqlt0 = veorq_p16(rql,vreinterpretq_p16_p8(vcombine_p8(uq4.val[0],uq6.val[0])));
  poly16x8_t sqt1 = vreinterpretq_p16_u64(vshlq_n_u64(vreinterpretq_u64_p8(vcombine_p8(uq4.val[1],uq6.val[1])), 8));
  poly8x8_t sdt2 = vreinterpret_p8_u64(vsri_n_u64(vreinterpret_u64_p8(vget_high_p8(vreinterpretq_p8_p16(sqt1))),vreinterpret_u64_p8(uq4.val[1]),56));
  poly8x8_t sdt3 = vreinterpret_p8_u64(vshr_n_u64(vreinterpret_u64_p8(uq6.val[1]),56));
  poly16x8_t rqlt4 = veorq_p16(rqlt0,vreinterpretq_p16_p8(vcombine_p8(vget_low_p8(vreinterpretq_p8_p16(sqt1)),sdt2)));
  poly16x8_t pq5 = vmull_p8(sdt3,k135);
  poly8x8_t xt6 = veor_p8(vget_low_p8(vreinterpretq_p8_p16(pq5)),vget_low_p8(vreinterpretq_p8_p16(rqlt4)));
  poly16x8_t f = vreinterpretq_p16_p8(vcombine_p8(xt6,vget_high_p8(vreinterpretq_p8_p16(rqlt4))));
  vst1q_p16((poly16_t*)a,f);
}


/* NEON based GCM, drop-in replacement if xlen == 16
   for the reference addmul.
   This need to bit-reverse inside byte
   before and after calling, to conform
   to GCM bit-ordering.
*/
void addmul_neon(unsigned char *a,
                 const unsigned char *x,
                 const unsigned long long xlen,
                 const unsigned char *y) {
  int i;
  unsigned char y2[16];
  unsigned char x2[16];
  /* ugly bit-reversal inside byte macro */
#define BR(x,y) ((uint32_t*)x)[i] = bswap32(rbit(((uint32_t*)y)[i]))
  for(i = 0 ; i < 4 ; i++) {
    BR(a,a);
    BR(x2,x);
    BR(y2,y);
  }
  addmul_neon_nobr(a,x2,xlen,y2);
  for(i = 0 ; i < 4 ; i++) {
    BR(a,a);
  } 
#undef BR
}
void addmul_start_neon(const unsigned char *c, const unsigned char *H) {
  /* nothing */
}
void addmul_finish_neon(unsigned char *c) {
  /* nothing */
}




#ifdef __TEST_FPGA__
typedef volatile unsigned int vuint;

volatile void *ptr;
int fd;
unsigned int page_offset;

void open_fpga(void) {
  unsigned int gpio_addr = 0x60000000;
  unsigned int page_addr;
  unsigned int page_size=sysconf(_SC_PAGESIZE);
  fd = open ("/dev/mem", O_RDWR);
  page_addr = (gpio_addr & (~(page_size-1)));
  page_offset = gpio_addr - page_addr;
  ptr = mmap(NULL, page_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, page_addr);
}

void close_fpga(void) {
  unsigned int page_size=sysconf(_SC_PAGESIZE);
  munmap(ptr, page_size);
  close(fd);
}

/* NEON load & store fail with Bus Error in the mmap()ed FPGA memory space ... */
static inline void mymemcpy_neon_m16(char *dst, const char *src, const size_t size) {
  size_t i = 0;
  for ( ; i < size ; i+= 16) {
    uint32x2_t t0 = vld1_u32((const uint32_t*)(src+i+ 0));
    uint32x2_t t1 = vld1_u32((const uint32_t*)(src+i+ 8));
    vst1_u32((uint32_t*)(dst+i+ 0), t0);
    vst1_u32((uint32_t*)(dst+i+ 8), t1);
  }
}
static inline void mymemcpy_noneon_m16(char *dst, const char *src, const size_t size) {
  size_t i = 0;
  for ( ; i < size ; i+= 16) {
    /* without the volatile, compilers optimized into NEON loads & stores... */
    uint32_t t0 = *((const volatile uint32_t*)(src+i+ 0));
    uint32_t t1 = *((const volatile uint32_t*)(src+i+ 4));
    uint32_t t2 = *((const volatile uint32_t*)(src+i+ 8));
    uint32_t t3 = *((const volatile uint32_t*)(src+i+12));
    *((volatile uint32_t*)(dst+i+ 0)) = t0;
    *((volatile uint32_t*)(dst+i+ 4)) = t1;
    *((volatile uint32_t*)(dst+i+ 8)) = t2;
    *((volatile uint32_t*)(dst+i+12)) = t3;
  }
}

//#define memcpy(a,b,c) mymemcpy_m16(a,b,c)
//#define memcpy(a,b,c) mymemcpy_noneon_m16(a,b,c)
/* only send a[] then run one GCM step on the
   internally kept accum ('c') and H ('b') */
void addmul_fpga(unsigned char *c,
                 const unsigned char *a, 
                 const unsigned long long xlen,
                 const unsigned char *b) {
  unsigned int t;
  int i;
  memcpy(ptr + page_offset + 0, a, 16);

  *((vuint*)(ptr + page_offset + 124)) = 0x0000000F; // start
  *((vuint*)(ptr + page_offset + 124)) = 0x0000000F; // start fixme:why do I need _two_ stores???
  // fixme: why don't I need the wait loop ? how fast is the fpga anyway ?
  //while ((t = *((vuint*)(ptr + page_offset + 124))) != 0) {
  //}
}
/* we send the start accum & H before starting */
void addmul_start_fpga(const unsigned char *c, const unsigned char *H) {
  memcpy(ptr + page_offset + 16, H, 16);
  memcpy(ptr + page_offset + 32, c, 16);
}
/* recover the accum */
void addmul_finish_fpga(unsigned char *c) {
  memcpy(c, ptr + page_offset + 32, 16);
}
#undef memcpy
#endif // __TEST_FPGA__
#endif


/* this simply accumulates the GCM hash for v of
   lenght vlen into accum using multiplicand H */
void do_gcm(unsigned char *accum, const unsigned char *H,
            const unsigned char *v, unsigned int vlen) {
  unsigned int i = 0;
  unsigned char temp[16];
#ifdef GCM_HAS_UNROLL8
  unsigned char Hn[16*8];
  compute_8power(H, Hn);
  for ( ; i < (vlen & ~127) ; i+=128) {
    addmul8(accum,v+i,Hn);
  }
#endif
  for ( ; i < (vlen & ~15) ; i+=16) {
    addmul(accum,v+i,16,H);
  }
  if (i != vlen) {
    memset(temp,0,16);
    memcpy(temp,v+i,vlen-i);
    addmul(accum,temp,16,H);
  }
}
/* this first does the XOR then accumulates the GCM hash for v of
   lenght vlen into accum using multiplicand H (i.e., for encryption) */
void do_xor_gcm(unsigned char *accum, const unsigned char *H,
                unsigned char *v, const unsigned char *in, unsigned int vlen) {
  unsigned int i = 0, j;
  unsigned char temp[16];
#ifdef GCM_HAS_UNROLL8
  unsigned char Hn[16*8];
  compute_8power(H, Hn);
  for ( ; i < (vlen & ~127) ; i+=128) {
    for (j = 0 ; j < 128 ; j++)
      v[i+j] ^= in[i+j];
    addmul8(accum,v+i,Hn);
  }
#endif
  for ( ; i < (vlen & ~15) ; i+=16) {
    for (j = 0 ; j < 16 ; j++)
      v[i+j] ^= in[i+j];
    addmul(accum,v+i,16,H);
  }
  if (i != vlen) {
    memset(temp,0,16);
    for (j = 0 ; j < vlen-i ; j++)
      v[i+j] ^= in[i+j];
    memcpy(temp,v+i,vlen-i);
    addmul(accum,temp,16,H);
  }
}
/* this first accumulates the GCM hash then does the XOR for v of
   lenght vlen into accum using multiplicand H (i.e., for decryption) */
void do_gcm_xor(unsigned char *accum, const unsigned char *H,
                unsigned char *v, const unsigned char *in, unsigned int vlen) {
  unsigned int i = 0, j;
  unsigned char temp[16];
#ifdef GCM_HAS_UNROLL8
  unsigned char Hn[16*8];
  compute_8power(H, Hn);
  for ( ; i < (vlen & ~127) ; i+=128) {
    addmul8(accum,v+i,Hn);
    for (j = 0 ; j < 128 ; j++)
      v[i+j] ^= in[i+j];
  }
#endif
  for ( ; i < (vlen & ~15) ; i+=16) {
    addmul(accum,v+i,16,H);
    for (j = 0 ; j < 16 ; j++)
      v[i+j] ^= in[i+j];
  }
  if (i != vlen) {
    memset(temp,0,16);
    memcpy(temp,v+i,vlen-i);
    addmul(accum,temp,16,H);
    for (j = 0 ; j < vlen-i ; j++)
      v[i+j] ^= in[i+j];
  }
}


#ifdef TEST_GCM
static void init(int i, uint32_t* H32, uint32_t* accum32, uint32_t* input32) {
  int j;
  srandom(i+1);
  for (j = 0 ; j < 4 ; j++) {
    H32[j] = random();
    accum32[j] = random();
    input32[j] = random();
  }
}

static void loop(const int max_size, unsigned char *accum, const unsigned char* finput,
                 const unsigned char *H,
                 addmul_proto f,
                 addmul_start_proto fs,
                 addmul_finish_proto fi) {
  int i;
  fs(accum, H);
  for (i = 0 ; i < max_size ; i+=16) {
    f(accum, finput+i, 16, H);
  } 
  fi(accum);
}
static void loop4(const int max_size, unsigned char *accum, const unsigned char* finput, const unsigned char *H, void (*f4)(unsigned char *, const unsigned char *, const unsigned char *), addmul_proto f) {
  int i;
  unsigned char Hn[16*4];
  compute_4power_pclmul(H, Hn); /* fixme */
  for (i = 0 ; i < max_size ; i+=64) {
    f4(accum, finput+i, Hn);
  } 
}
static void loop8(const int max_size, unsigned char *accum, const unsigned char* finput, const unsigned char *H, void (*f8)(unsigned char *, const unsigned char *, const unsigned char *), addmul_proto f) {
  int i;
  unsigned char Hn[16*8];
  compute_8power_pclmul(H, Hn); /* fixme */
  for (i = 0 ; i < max_size ; i+=128) {
    f8(accum, finput+i, Hn);
  } 
}

#ifndef MAX_SIZE
#define MAX_SIZE (4*1024*1024)
#endif
int main(int argc, char **argv) {
  unsigned char H[16] __attribute__ ((aligned (16)));
  unsigned char input[16] __attribute__ ((aligned (16)));
  unsigned char accum_ref[16] __attribute__ ((aligned (16)));
  unsigned char accum_neon[16] __attribute__ ((aligned (16)));
  unsigned char accum_pclmul[16] __attribute__ ((aligned (16)));
  unsigned char accum_fpga[16] __attribute__ ((aligned (16)));
  unsigned char *finput;
  uint32_t* H32 = (uint32_t*)H;
  uint32_t* accum_ref32 = (uint32_t*)accum_ref;
  uint32_t* accum_neon32 = (uint32_t*)accum_neon;
  uint32_t* accum_pclmul32 = (uint32_t*)accum_pclmul;
  uint32_t* accum_fpga32 = (uint32_t*)accum_fpga;
  uint32_t* input32 = (uint32_t*)input;
  uint32_t* finput32;
  int i, j;
  int ok = 1;
  
  printf("Testing validity... ");
  for (i = 0 ; i < 20 && ok ; i++) {
#define TEST_IMPL(X)                                                    \
    do {                                                                \
      init(i, H32, accum_##X##32, input32);                             \
      addmul_start_##X(accum_##X, H);                                   \
      addmul_##X(accum_##X, input, 16, H);                              \
      addmul_finish_##X(accum_##X);                                     \
      /* printf("%d: "#X" = 0x%08x 0x%08x 0x%08x 0x%08x\n", i, accum_##X##32[0], accum_##X##32[1], accum_##X##32[2], accum_##X##32[3]); */ \
      for (j = 0 ; j < 4 ; j++) {                                       \
        if (accum_##X##32[j] != accum_ref32[j]) {                       \
          printf("%d: "#X" has an issue @ %d -> 0x%08x != 0x%08x\n", i, j, accum_##X##32[j], accum_ref32[j]); \
          ok = 0;                                                       \
        }                                                               \
      } } while (0)
    
    TEST_IMPL(ref);
#if defined(__arm__) || defined(__aarch64__)
    TEST_IMPL(neon);
#endif
#if defined(__PCLMUL__)
    TEST_IMPL(pclmul);
#endif
#if defined(__TEST_FPGA__)
    open_fpga();
    TEST_IMPL(fpga);
    close_fpga();
#endif
#undef TEST_IMPL
  }
  printf("%s\n", ok ? "OK" : "FAILED");
  if (!ok)
    return -1;

  printf("Testing speed...\n");
  
  finput = (unsigned char*)malloc(MAX_SIZE);
  finput32 = (uint32_t*)finput;
  srandom(100);
  for (j = 0 ; j < 4 ; j++) {
    H32[j] = random();
  }
  
  for (i = 0 ; i < MAX_SIZE/sizeof(uint32_t) ; i++)
    finput32[i] = random();

#define TEST_IMPL(X)                                                    \
  do {                                                                  \
    double t0 = wallclock(), t1;                                        \
    for (j = 0 ; j < 4 ; j++) {                                         \
      accum_##X##32[j] = 0;                                             \
    }                                                                   \
    loop(MAX_SIZE, accum_##X, finput, H, &addmul_##X,                   \
         &addmul_start_##X, &addmul_finish_##X);                        \
    t1 = wallclock();                                                   \
    printf(""#X": %d bytes in %lf seconds -> %lf MB/s", MAX_SIZE, t1-t0, (double)MAX_SIZE/(1000000.*(t1-t0))); \
    if ((accum_##X##32[0] != accum_ref32[0]) ||                         \
        (accum_##X##32[1] != accum_ref32[1]) ||                         \
        (accum_##X##32[2] != accum_ref32[2]) ||                         \
        (accum_##X##32[3] != accum_ref32[3]))                           \
      printf(" WRONG\n");                                               \
    else                                                                \
      printf("\n");                                                     \
  } while(0)
#define TEST_IMPL4(X)                                                   \
  do {                                                                  \
    double t0 = wallclock(), t1;                                        \
    for (j = 0 ; j < 4 ; j++) {                                         \
      accum_##X##32[j] = 0;                                             \
    }                                                                   \
    loop4(MAX_SIZE, accum_##X, finput, H, &addmul4_##X, &addmul_##X); \
    t1 = wallclock();                                                   \
    printf(""#X"4: %d bytes in %lf seconds -> %lf MB/s", MAX_SIZE, t1-t0, (double)MAX_SIZE/(1000000.*(t1-t0))); \
    if ((accum_##X##32[0] != accum_ref32[0]) ||                         \
        (accum_##X##32[1] != accum_ref32[1]) ||                         \
        (accum_##X##32[2] != accum_ref32[2]) ||                         \
        (accum_##X##32[3] != accum_ref32[3]))                           \
      printf(" WRONG [0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x]\n", \
             accum_##X##32[0], accum_ref32[0], accum_##X##32[1], accum_ref32[1], accum_##X##32[2], accum_ref32[2], accum_##X##32[3], accum_ref32[3]); \
    else                                                                \
      printf("\n");                                                     \
  } while(0)
#define TEST_IMPL8(X)                                                   \
  do {                                                                  \
    double t0 = wallclock(), t1;                                        \
    for (j = 0 ; j < 4 ; j++) {                                         \
      accum_##X##32[j] = 0;                                             \
    }                                                                   \
    loop8(MAX_SIZE, accum_##X, finput, H, &addmul8_##X, &addmul_##X);   \
    t1 = wallclock();                                                   \
    printf(""#X"8: %d bytes in %lf seconds -> %lf MB/s", MAX_SIZE, t1-t0, (double)MAX_SIZE/(1000000.*(t1-t0))); \
    if ((accum_##X##32[0] != accum_ref32[0]) ||                         \
        (accum_##X##32[1] != accum_ref32[1]) ||                         \
        (accum_##X##32[2] != accum_ref32[2]) ||                         \
        (accum_##X##32[3] != accum_ref32[3]))                           \
      printf(" WRONG [0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x, 0x%08x <-> 0x%08x]\n", \
             accum_##X##32[0], accum_ref32[0], accum_##X##32[1], accum_ref32[1], accum_##X##32[2], accum_ref32[2], accum_##X##32[3], accum_ref32[3]); \
    else                                                                \
      printf("\n");                                                     \
  } while(0)

  TEST_IMPL(ref);
  TEST_IMPL(ref);
  TEST_IMPL(ref);
#if defined(__arm__) || defined(__aarch64__)
  TEST_IMPL(neon);
  TEST_IMPL(neon);
  TEST_IMPL(neon);
#endif
#if defined(__PCLMUL__)
  TEST_IMPL(pclmul);
  TEST_IMPL(pclmul);
  TEST_IMPL(pclmul);
  TEST_IMPL4(pclmul);
  TEST_IMPL4(pclmul);
  TEST_IMPL4(pclmul);
  TEST_IMPL8(pclmul);
  TEST_IMPL8(pclmul);
  TEST_IMPL8(pclmul);
#endif
#if defined(__TEST_FPGA__)
  open_fpga();
  TEST_IMPL(fpga);
  TEST_IMPL(fpga);
  TEST_IMPL(fpga);
  close_fpga();
#endif
#undef TEST_IMPL

 free(finput);

 return 0;
}
#endif
