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

#ifndef _AES_SCALAR_
#define _AES_SCALAR_

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

#ifdef __INTEL_COMPILER
#define ALIGN16 __declspec(align(16))
#define ALIGN32 __declspec(align(32))
#define ALIGN64 __declspec(align(64))
#else // assume GCC
#define ALIGN16  __attribute__((aligned(16)))
#define ALIGN32  __attribute__((aligned(32)))
#define ALIGN64  __attribute__((aligned(64)))
#define _bswap64(a) __builtin_bswap64(a)
#define _bswap(a) __builtin_bswap32(a)
#endif

#ifndef RSb__1
#define RSb__1 RSb__A
#endif
#ifndef RSb__2
#define RSb__2 RSb__B
#endif

#ifndef KT0__1
#define KT0__1 KT0__A
#endif
#ifndef KT0__2
#define KT0__2 KT0__B
#endif

#ifndef RT0__1
#define RT0__1 RT0__A
#endif
#ifndef RT0__2
#define RT0__2 RT0__B
#endif

#ifndef NOCOPY
/* we can't use those array directly in NOCOPY, at
   least until cudaHOstRegister works won Jetson TK1 ... */
#ifndef FT0
#define FT0 FT0_
#endif
#ifndef FT1
#define FT1 FT1_
#endif
#ifndef FT2
#define FT2 FT2_
#endif
#ifndef FT3
#define FT3 FT3_
#endif
#ifndef FSb
#define FSb FSb_
#endif
#else
extern uint32_t* FT0;
extern uint32_t* FT1;
extern uint32_t* FT2;
extern uint32_t* FT3;
extern uint32_t* FSb;
#endif

#ifndef RCON
#define RCON RCON__B
#endif

#define GCC

#define f_FSb_32__1(x) 	((FSb[((x) >> 24) &0xFF] << 24) ^ \
                         (FSb[((x) >> 16) &0xFF] << 16))

#define f_FSb_32__2(x) 	((FSb[((x) >>  8) &0xFF] <<  8 ) ^ \
                         (FSb[((x)      ) &0xFF] & 0xFF))

#define FSbData32bits   \
        {       \
        0x63636363, 0x7c7c7c7c, 0x77777777, 0x7b7b7b7b, 0xf2f2f2f2, 0x6b6b6b6b, 0x6f6f6f6f, 0xc5c5c5c5, \
        0x30303030, 0x01010101, 0x67676767, 0x2b2b2b2b, 0xfefefefe, 0xd7d7d7d7, 0xabababab, 0x76767676, \
        0xcacacaca, 0x82828282, 0xc9c9c9c9, 0x7d7d7d7d, 0xfafafafa, 0x59595959, 0x47474747, 0xf0f0f0f0, \
        0xadadadad, 0xd4d4d4d4, 0xa2a2a2a2, 0xafafafaf, 0x9c9c9c9c, 0xa4a4a4a4, 0x72727272, 0xc0c0c0c0, \
        0xb7b7b7b7, 0xfdfdfdfd, 0x93939393, 0x26262626, 0x36363636, 0x3f3f3f3f, 0xf7f7f7f7, 0xcccccccc, \
        0x34343434, 0xa5a5a5a5, 0xe5e5e5e5, 0xf1f1f1f1, 0x71717171, 0xd8d8d8d8, 0x31313131, 0x15151515, \
        0x04040404, 0xc7c7c7c7, 0x23232323, 0xc3c3c3c3, 0x18181818, 0x96969696, 0x05050505, 0x9a9a9a9a, \
        0x07070707, 0x12121212, 0x80808080, 0xe2e2e2e2, 0xebebebeb, 0x27272727, 0xb2b2b2b2, 0x75757575, \
        0x09090909, 0x83838383, 0x2c2c2c2c, 0x1a1a1a1a, 0x1b1b1b1b, 0x6e6e6e6e, 0x5a5a5a5a, 0xa0a0a0a0, \
        0x52525252, 0x3b3b3b3b, 0xd6d6d6d6, 0xb3b3b3b3, 0x29292929, 0xe3e3e3e3, 0x2f2f2f2f, 0x84848484, \
        0x53535353, 0xd1d1d1d1, 0x00000000, 0xedededed, 0x20202020, 0xfcfcfcfc, 0xb1b1b1b1, 0x5b5b5b5b, \
        0x6a6a6a6a, 0xcbcbcbcb, 0xbebebebe, 0x39393939, 0x4a4a4a4a, 0x4c4c4c4c, 0x58585858, 0xcfcfcfcf, \
        0xd0d0d0d0, 0xefefefef, 0xaaaaaaaa, 0xfbfbfbfb, 0x43434343, 0x4d4d4d4d, 0x33333333, 0x85858585, \
        0x45454545, 0xf9f9f9f9, 0x02020202, 0x7f7f7f7f, 0x50505050, 0x3c3c3c3c, 0x9f9f9f9f, 0xa8a8a8a8, \
        0x51515151, 0xa3a3a3a3, 0x40404040, 0x8f8f8f8f, 0x92929292, 0x9d9d9d9d, 0x38383838, 0xf5f5f5f5, \
        0xbcbcbcbc, 0xb6b6b6b6, 0xdadadada, 0x21212121, 0x10101010, 0xffffffff, 0xf3f3f3f3, 0xd2d2d2d2, \
        0xcdcdcdcd, 0x0c0c0c0c, 0x13131313, 0xecececec, 0x5f5f5f5f, 0x97979797, 0x44444444, 0x17171717, \
        0xc4c4c4c4, 0xa7a7a7a7, 0x7e7e7e7e, 0x3d3d3d3d, 0x64646464, 0x5d5d5d5d, 0x19191919, 0x73737373, \
        0x60606060, 0x81818181, 0x4f4f4f4f, 0xdcdcdcdc, 0x22222222, 0x2a2a2a2a, 0x90909090, 0x88888888, \
        0x46464646, 0xeeeeeeee, 0xb8b8b8b8, 0x14141414, 0xdededede, 0x5e5e5e5e, 0x0b0b0b0b, 0xdbdbdbdb, \
        0xe0e0e0e0, 0x32323232, 0x3a3a3a3a, 0x0a0a0a0a, 0x49494949, 0x06060606, 0x24242424, 0x5c5c5c5c, \
        0xc2c2c2c2, 0xd3d3d3d3, 0xacacacac, 0x62626262, 0x91919191, 0x95959595, 0xe4e4e4e4, 0x79797979, \
        0xe7e7e7e7, 0xc8c8c8c8, 0x37373737, 0x6d6d6d6d, 0x8d8d8d8d, 0xd5d5d5d5, 0x4e4e4e4e, 0xa9a9a9a9, \
        0x6c6c6c6c, 0x56565656, 0xf4f4f4f4, 0xeaeaeaea, 0x65656565, 0x7a7a7a7a, 0xaeaeaeae, 0x08080808, \
        0xbabababa, 0x78787878, 0x25252525, 0x2e2e2e2e, 0x1c1c1c1c, 0xa6a6a6a6, 0xb4b4b4b4, 0xc6c6c6c6, \
        0xe8e8e8e8, 0xdddddddd, 0x74747474, 0x1f1f1f1f, 0x4b4b4b4b, 0xbdbdbdbd, 0x8b8b8b8b, 0x8a8a8a8a, \
        0x70707070, 0x3e3e3e3e, 0xb5b5b5b5, 0x66666666, 0x48484848, 0x03030303, 0xf6f6f6f6, 0x0e0e0e0e, \
        0x61616161, 0x35353535, 0x57575757, 0xb9b9b9b9, 0x86868686, 0xc1c1c1c1, 0x1d1d1d1d, 0x9e9e9e9e, \
        0xe1e1e1e1, 0xf8f8f8f8, 0x98989898, 0x11111111, 0x69696969, 0xd9d9d9d9, 0x8e8e8e8e, 0x94949494, \
        0x9b9b9b9b, 0x1e1e1e1e, 0x87878787, 0xe9e9e9e9, 0xcececece, 0x55555555, 0x28282828, 0xdfdfdfdf, \
        0x8c8c8c8c, 0xa1a1a1a1, 0x89898989, 0x0d0d0d0d, 0xbfbfbfbf, 0xe6e6e6e6, 0x42424242, 0x68686868, \
        0x41414141, 0x99999999, 0x2d2d2d2d, 0x0f0f0f0f, 0xb0b0b0b0, 0x54545454, 0xbbbbbbbb, 0x16161616  \
        }

static uint32_t FSb32__A[256] = FSbData32bits;
static uint32_t FSb32__B[256] = FSbData32bits;
#undef FSbData32bits

#define RSbData32bits   \
        {       \
        0x52525252, 0x09090909, 0x6a6a6a6a, 0xd5d5d5d5, 0x30303030, 0x36363636, 0xa5a5a5a5, 0x38383838, \
        0xbfbfbfbf, 0x40404040, 0xa3a3a3a3, 0x9e9e9e9e, 0x81818181, 0xf3f3f3f3, 0xd7d7d7d7, 0xfbfbfbfb, \
        0x7c7c7c7c, 0xe3e3e3e3, 0x39393939, 0x82828282, 0x9b9b9b9b, 0x2f2f2f2f, 0xffffffff, 0x87878787, \
        0x34343434, 0x8e8e8e8e, 0x43434343, 0x44444444, 0xc4c4c4c4, 0xdededede, 0xe9e9e9e9, 0xcbcbcbcb, \
        0x54545454, 0x7b7b7b7b, 0x94949494, 0x32323232, 0xa6a6a6a6, 0xc2c2c2c2, 0x23232323, 0x3d3d3d3d, \
        0xeeeeeeee, 0x4c4c4c4c, 0x95959595, 0x0b0b0b0b, 0x42424242, 0xfafafafa, 0xc3c3c3c3, 0x4e4e4e4e, \
        0x08080808, 0x2e2e2e2e, 0xa1a1a1a1, 0x66666666, 0x28282828, 0xd9d9d9d9, 0x24242424, 0xb2b2b2b2, \
        0x76767676, 0x5b5b5b5b, 0xa2a2a2a2, 0x49494949, 0x6d6d6d6d, 0x8b8b8b8b, 0xd1d1d1d1, 0x25252525, \
        0x72727272, 0xf8f8f8f8, 0xf6f6f6f6, 0x64646464, 0x86868686, 0x68686868, 0x98989898, 0x16161616, \
        0xd4d4d4d4, 0xa4a4a4a4, 0x5c5c5c5c, 0xcccccccc, 0x5d5d5d5d, 0x65656565, 0xb6b6b6b6, 0x92929292, \
        0x6c6c6c6c, 0x70707070, 0x48484848, 0x50505050, 0xfdfdfdfd, 0xedededed, 0xb9b9b9b9, 0xdadadada, \
        0x5e5e5e5e, 0x15151515, 0x46464646, 0x57575757, 0xa7a7a7a7, 0x8d8d8d8d, 0x9d9d9d9d, 0x84848484, \
        0x90909090, 0xd8d8d8d8, 0xabababab, 0x00000000, 0x8c8c8c8c, 0xbcbcbcbc, 0xd3d3d3d3, 0x0a0a0a0a, \
        0xf7f7f7f7, 0xe4e4e4e4, 0x58585858, 0x05050505, 0xb8b8b8b8, 0xb3b3b3b3, 0x45454545, 0x06060606, \
        0xd0d0d0d0, 0x2c2c2c2c, 0x1e1e1e1e, 0x8f8f8f8f, 0xcacacaca, 0x3f3f3f3f, 0x0f0f0f0f, 0x02020202, \
        0xc1c1c1c1, 0xafafafaf, 0xbdbdbdbd, 0x03030303, 0x01010101, 0x13131313, 0x8a8a8a8a, 0x6b6b6b6b, \
        0x3a3a3a3a, 0x91919191, 0x11111111, 0x41414141, 0x4f4f4f4f, 0x67676767, 0xdcdcdcdc, 0xeaeaeaea, \
        0x97979797, 0xf2f2f2f2, 0xcfcfcfcf, 0xcececece, 0xf0f0f0f0, 0xb4b4b4b4, 0xe6e6e6e6, 0x73737373, \
        0x96969696, 0xacacacac, 0x74747474, 0x22222222, 0xe7e7e7e7, 0xadadadad, 0x35353535, 0x85858585, \
        0xe2e2e2e2, 0xf9f9f9f9, 0x37373737, 0xe8e8e8e8, 0x1c1c1c1c, 0x75757575, 0xdfdfdfdf, 0x6e6e6e6e, \
        0x47474747, 0xf1f1f1f1, 0x1a1a1a1a, 0x71717171, 0x1d1d1d1d, 0x29292929, 0xc5c5c5c5, 0x89898989, \
        0x6f6f6f6f, 0xb7b7b7b7, 0x62626262, 0x0e0e0e0e, 0xaaaaaaaa, 0x18181818, 0xbebebebe, 0x1b1b1b1b, \
        0xfcfcfcfc, 0x56565656, 0x3e3e3e3e, 0x4b4b4b4b, 0xc6c6c6c6, 0xd2d2d2d2, 0x79797979, 0x20202020, \
        0x9a9a9a9a, 0xdbdbdbdb, 0xc0c0c0c0, 0xfefefefe, 0x78787878, 0xcdcdcdcd, 0x5a5a5a5a, 0xf4f4f4f4, \
        0x1f1f1f1f, 0xdddddddd, 0xa8a8a8a8, 0x33333333, 0x88888888, 0x07070707, 0xc7c7c7c7, 0x31313131, \
        0xb1b1b1b1, 0x12121212, 0x10101010, 0x59595959, 0x27272727, 0x80808080, 0xecececec, 0x5f5f5f5f, \
        0x60606060, 0x51515151, 0x7f7f7f7f, 0xa9a9a9a9, 0x19191919, 0xb5b5b5b5, 0x4a4a4a4a, 0x0d0d0d0d, \
        0x2d2d2d2d, 0xe5e5e5e5, 0x7a7a7a7a, 0x9f9f9f9f, 0x93939393, 0xc9c9c9c9, 0x9c9c9c9c, 0xefefefef, \
        0xa0a0a0a0, 0xe0e0e0e0, 0x3b3b3b3b, 0x4d4d4d4d, 0xaeaeaeae, 0x2a2a2a2a, 0xf5f5f5f5, 0xb0b0b0b0, \
        0xc8c8c8c8, 0xebebebeb, 0xbbbbbbbb, 0x3c3c3c3c, 0x83838383, 0x53535353, 0x99999999, 0x61616161, \
        0x17171717, 0x2b2b2b2b, 0x04040404, 0x7e7e7e7e, 0xbabababa, 0x77777777, 0xd6d6d6d6, 0x26262626, \
        0xe1e1e1e1, 0x69696969, 0x14141414, 0x63636363, 0x55555555, 0x21212121, 0x0c0c0c0c, 0x7d7d7d7d  \
        }


static uint32_t RSb32__A[256] = RSbData32bits;
static uint32_t RSb32__B[256] = RSbData32bits;
#undef RSbData32bits

#define FSbData                                         \
  {                                                     \
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,     \
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,     \
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,     \
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,     \
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,     \
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,     \
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,     \
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,     \
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,     \
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,     \
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,     \
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,     \
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,     \
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,     \
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,     \
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,     \
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,     \
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,     \
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,     \
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,     \
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,     \
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,     \
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,     \
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,     \
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,     \
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,     \
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,     \
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,     \
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,     \
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,     \
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,     \
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16      \
  }

static uint32_t FSb_[256] = FSbData;
#undef FSbData

#define KT0Data                                         \
  {                                                     \
    0x0 ,0xE090D0B ,0x1C121A16 ,0x121B171D ,            \
    0x3824342C ,0x362D3927 ,0x24362E3A ,0x2A3F2331 ,    \
    0x70486858 ,0x7E416553 ,0x6C5A724E ,0x62537F45 ,    \
    0x486C5C74 ,0x4665517F ,0x547E4662 ,0x5A774B69 ,    \
    0xE090D0B0 ,0xEE99DDBB ,0xFC82CAA6 ,0xF28BC7AD ,    \
    0xD8B4E49C ,0xD6BDE997 ,0xC4A6FE8A ,0xCAAFF381 ,    \
    0x90D8B8E8 ,0x9ED1B5E3 ,0x8CCAA2FE ,0x82C3AFF5 ,    \
    0xA8FC8CC4 ,0xA6F581CF ,0xB4EE96D2 ,0xBAE79BD9 ,    \
    0xDB3BBB7B ,0xD532B670 ,0xC729A16D ,0xC920AC66 ,    \
    0xE31F8F57 ,0xED16825C ,0xFF0D9541 ,0xF104984A ,    \
    0xAB73D323 ,0xA57ADE28 ,0xB761C935 ,0xB968C43E ,    \
    0x9357E70F ,0x9D5EEA04 ,0x8F45FD19 ,0x814CF012 ,    \
    0x3BAB6BCB ,0x35A266C0 ,0x27B971DD ,0x29B07CD6 ,    \
    0x38F5FE7 ,0xD8652EC ,0x1F9D45F1 ,0x119448FA ,      \
    0x4BE30393 ,0x45EA0E98 ,0x57F11985 ,0x59F8148E ,    \
    0x73C737BF ,0x7DCE3AB4 ,0x6FD52DA9 ,0x61DC20A2 ,    \
    0xAD766DF6 ,0xA37F60FD ,0xB16477E0 ,0xBF6D7AEB ,    \
    0x955259DA ,0x9B5B54D1 ,0x894043CC ,0x87494EC7 ,    \
    0xDD3E05AE ,0xD33708A5 ,0xC12C1FB8 ,0xCF2512B3 ,    \
    0xE51A3182 ,0xEB133C89 ,0xF9082B94 ,0xF701269F ,    \
    0x4DE6BD46 ,0x43EFB04D ,0x51F4A750 ,0x5FFDAA5B ,    \
    0x75C2896A ,0x7BCB8461 ,0x69D0937C ,0x67D99E77 ,    \
    0x3DAED51E ,0x33A7D815 ,0x21BCCF08 ,0x2FB5C203 ,    \
    0x58AE132 ,0xB83EC39 ,0x1998FB24 ,0x1791F62F ,      \
    0x764DD68D ,0x7844DB86 ,0x6A5FCC9B ,0x6456C190 ,    \
    0x4E69E2A1 ,0x4060EFAA ,0x527BF8B7 ,0x5C72F5BC ,    \
    0x605BED5 ,0x80CB3DE ,0x1A17A4C3 ,0x141EA9C8 ,      \
    0x3E218AF9 ,0x302887F2 ,0x223390EF ,0x2C3A9DE4 ,    \
    0x96DD063D ,0x98D40B36 ,0x8ACF1C2B ,0x84C61120 ,    \
    0xAEF93211 ,0xA0F03F1A ,0xB2EB2807 ,0xBCE2250C ,    \
    0xE6956E65 ,0xE89C636E ,0xFA877473 ,0xF48E7978 ,    \
    0xDEB15A49 ,0xD0B85742 ,0xC2A3405F ,0xCCAA4D54 ,    \
    0x41ECDAF7 ,0x4FE5D7FC ,0x5DFEC0E1 ,0x53F7CDEA ,    \
    0x79C8EEDB ,0x77C1E3D0 ,0x65DAF4CD ,0x6BD3F9C6 ,    \
    0x31A4B2AF ,0x3FADBFA4 ,0x2DB6A8B9 ,0x23BFA5B2 ,    \
    0x9808683 ,0x7898B88 ,0x15929C95 ,0x1B9B919E ,      \
    0xA17C0A47 ,0xAF75074C ,0xBD6E1051 ,0xB3671D5A ,    \
    0x99583E6B ,0x97513360 ,0x854A247D ,0x8B432976 ,    \
    0xD134621F ,0xDF3D6F14 ,0xCD267809 ,0xC32F7502 ,    \
    0xE9105633 ,0xE7195B38 ,0xF5024C25 ,0xFB0B412E ,    \
    0x9AD7618C ,0x94DE6C87 ,0x86C57B9A ,0x88CC7691 ,    \
    0xA2F355A0 ,0xACFA58AB ,0xBEE14FB6 ,0xB0E842BD ,    \
    0xEA9F09D4 ,0xE49604DF ,0xF68D13C2 ,0xF8841EC9 ,    \
    0xD2BB3DF8 ,0xDCB230F3 ,0xCEA927EE ,0xC0A02AE5 ,    \
    0x7A47B13C ,0x744EBC37 ,0x6655AB2A ,0x685CA621 ,    \
    0x42638510 ,0x4C6A881B ,0x5E719F06 ,0x5078920D ,    \
    0xA0FD964 ,0x406D46F ,0x161DC372 ,0x1814CE79 ,      \
    0x322BED48 ,0x3C22E043 ,0x2E39F75E ,0x2030FA55 ,    \
    0xEC9AB701 ,0xE293BA0A ,0xF088AD17 ,0xFE81A01C ,    \
    0xD4BE832D ,0xDAB78E26 ,0xC8AC993B ,0xC6A59430 ,    \
    0x9CD2DF59 ,0x92DBD252 ,0x80C0C54F ,0x8EC9C844 ,    \
    0xA4F6EB75 ,0xAAFFE67E ,0xB8E4F163 ,0xB6EDFC68 ,    \
    0xC0A67B1 ,0x2036ABA ,0x10187DA7 ,0x1E1170AC ,      \
    0x342E539D ,0x3A275E96 ,0x283C498B ,0x26354480 ,    \
    0x7C420FE9 ,0x724B02E2 ,0x605015FF ,0x6E5918F4 ,    \
    0x44663BC5 ,0x4A6F36CE ,0x587421D3 ,0x567D2CD8 ,    \
    0x37A10C7A ,0x39A80171 ,0x2BB3166C ,0x25BA1B67 ,    \
    0xF853856 ,0x18C355D ,0x13972240 ,0x1D9E2F4B ,      \
    0x47E96422 ,0x49E06929 ,0x5BFB7E34 ,0x55F2733F ,    \
    0x7FCD500E ,0x71C45D05 ,0x63DF4A18 ,0x6DD64713 ,    \
    0xD731DCCA ,0xD938D1C1 ,0xCB23C6DC ,0xC52ACBD7 ,    \
    0xEF15E8E6 ,0xE11CE5ED ,0xF307F2F0 ,0xFD0EFFFB ,    \
    0xA779B492 ,0xA970B999 ,0xBB6BAE84 ,0xB562A38F ,    \
    0x9F5D80BE ,0x91548DB5 ,0x834F9AA8 ,0x8D4697A3      \
  }

static uint32_t KT0__A[256]= KT0Data;
static uint32_t KT0__B[256]= KT0Data;
#undef KT0Data

  /* forward table */

#define FT \
\
    V(C6,63,63,A5), V(F8,7C,7C,84), V(EE,77,77,99), V(F6,7B,7B,8D), \
    V(FF,F2,F2,0D), V(D6,6B,6B,BD), V(DE,6F,6F,B1), V(91,C5,C5,54), \
    V(60,30,30,50), V(02,01,01,03), V(CE,67,67,A9), V(56,2B,2B,7D), \
    V(E7,FE,FE,19), V(B5,D7,D7,62), V(4D,AB,AB,E6), V(EC,76,76,9A), \
    V(8F,CA,CA,45), V(1F,82,82,9D), V(89,C9,C9,40), V(FA,7D,7D,87), \
    V(EF,FA,FA,15), V(B2,59,59,EB), V(8E,47,47,C9), V(FB,F0,F0,0B), \
    V(41,AD,AD,EC), V(B3,D4,D4,67), V(5F,A2,A2,FD), V(45,AF,AF,EA), \
    V(23,9C,9C,BF), V(53,A4,A4,F7), V(E4,72,72,96), V(9B,C0,C0,5B), \
    V(75,B7,B7,C2), V(E1,FD,FD,1C), V(3D,93,93,AE), V(4C,26,26,6A), \
    V(6C,36,36,5A), V(7E,3F,3F,41), V(F5,F7,F7,02), V(83,CC,CC,4F), \
    V(68,34,34,5C), V(51,A5,A5,F4), V(D1,E5,E5,34), V(F9,F1,F1,08), \
    V(E2,71,71,93), V(AB,D8,D8,73), V(62,31,31,53), V(2A,15,15,3F), \
    V(08,04,04,0C), V(95,C7,C7,52), V(46,23,23,65), V(9D,C3,C3,5E), \
    V(30,18,18,28), V(37,96,96,A1), V(0A,05,05,0F), V(2F,9A,9A,B5), \
    V(0E,07,07,09), V(24,12,12,36), V(1B,80,80,9B), V(DF,E2,E2,3D), \
    V(CD,EB,EB,26), V(4E,27,27,69), V(7F,B2,B2,CD), V(EA,75,75,9F), \
    V(12,09,09,1B), V(1D,83,83,9E), V(58,2C,2C,74), V(34,1A,1A,2E), \
    V(36,1B,1B,2D), V(DC,6E,6E,B2), V(B4,5A,5A,EE), V(5B,A0,A0,FB), \
    V(A4,52,52,F6), V(76,3B,3B,4D), V(B7,D6,D6,61), V(7D,B3,B3,CE), \
    V(52,29,29,7B), V(DD,E3,E3,3E), V(5E,2F,2F,71), V(13,84,84,97), \
    V(A6,53,53,F5), V(B9,D1,D1,68), V(00,00,00,00), V(C1,ED,ED,2C), \
    V(40,20,20,60), V(E3,FC,FC,1F), V(79,B1,B1,C8), V(B6,5B,5B,ED), \
    V(D4,6A,6A,BE), V(8D,CB,CB,46), V(67,BE,BE,D9), V(72,39,39,4B), \
    V(94,4A,4A,DE), V(98,4C,4C,D4), V(B0,58,58,E8), V(85,CF,CF,4A), \
    V(BB,D0,D0,6B), V(C5,EF,EF,2A), V(4F,AA,AA,E5), V(ED,FB,FB,16), \
    V(86,43,43,C5), V(9A,4D,4D,D7), V(66,33,33,55), V(11,85,85,94), \
    V(8A,45,45,CF), V(E9,F9,F9,10), V(04,02,02,06), V(FE,7F,7F,81), \
    V(A0,50,50,F0), V(78,3C,3C,44), V(25,9F,9F,BA), V(4B,A8,A8,E3), \
    V(A2,51,51,F3), V(5D,A3,A3,FE), V(80,40,40,C0), V(05,8F,8F,8A), \
    V(3F,92,92,AD), V(21,9D,9D,BC), V(70,38,38,48), V(F1,F5,F5,04), \
    V(63,BC,BC,DF), V(77,B6,B6,C1), V(AF,DA,DA,75), V(42,21,21,63), \
    V(20,10,10,30), V(E5,FF,FF,1A), V(FD,F3,F3,0E), V(BF,D2,D2,6D), \
    V(81,CD,CD,4C), V(18,0C,0C,14), V(26,13,13,35), V(C3,EC,EC,2F), \
    V(BE,5F,5F,E1), V(35,97,97,A2), V(88,44,44,CC), V(2E,17,17,39), \
    V(93,C4,C4,57), V(55,A7,A7,F2), V(FC,7E,7E,82), V(7A,3D,3D,47), \
    V(C8,64,64,AC), V(BA,5D,5D,E7), V(32,19,19,2B), V(E6,73,73,95), \
    V(C0,60,60,A0), V(19,81,81,98), V(9E,4F,4F,D1), V(A3,DC,DC,7F), \
    V(44,22,22,66), V(54,2A,2A,7E), V(3B,90,90,AB), V(0B,88,88,83), \
    V(8C,46,46,CA), V(C7,EE,EE,29), V(6B,B8,B8,D3), V(28,14,14,3C), \
    V(A7,DE,DE,79), V(BC,5E,5E,E2), V(16,0B,0B,1D), V(AD,DB,DB,76), \
    V(DB,E0,E0,3B), V(64,32,32,56), V(74,3A,3A,4E), V(14,0A,0A,1E), \
    V(92,49,49,DB), V(0C,06,06,0A), V(48,24,24,6C), V(B8,5C,5C,E4), \
    V(9F,C2,C2,5D), V(BD,D3,D3,6E), V(43,AC,AC,EF), V(C4,62,62,A6), \
    V(39,91,91,A8), V(31,95,95,A4), V(D3,E4,E4,37), V(F2,79,79,8B), \
    V(D5,E7,E7,32), V(8B,C8,C8,43), V(6E,37,37,59), V(DA,6D,6D,B7), \
    V(01,8D,8D,8C), V(B1,D5,D5,64), V(9C,4E,4E,D2), V(49,A9,A9,E0), \
    V(D8,6C,6C,B4), V(AC,56,56,FA), V(F3,F4,F4,07), V(CF,EA,EA,25), \
    V(CA,65,65,AF), V(F4,7A,7A,8E), V(47,AE,AE,E9), V(10,08,08,18), \
    V(6F,BA,BA,D5), V(F0,78,78,88), V(4A,25,25,6F), V(5C,2E,2E,72), \
    V(38,1C,1C,24), V(57,A6,A6,F1), V(73,B4,B4,C7), V(97,C6,C6,51), \
    V(CB,E8,E8,23), V(A1,DD,DD,7C), V(E8,74,74,9C), V(3E,1F,1F,21), \
    V(96,4B,4B,DD), V(61,BD,BD,DC), V(0D,8B,8B,86), V(0F,8A,8A,85), \
    V(E0,70,70,90), V(7C,3E,3E,42), V(71,B5,B5,C4), V(CC,66,66,AA), \
    V(90,48,48,D8), V(06,03,03,05), V(F7,F6,F6,01), V(1C,0E,0E,12), \
    V(C2,61,61,A3), V(6A,35,35,5F), V(AE,57,57,F9), V(69,B9,B9,D0), \
    V(17,86,86,91), V(99,C1,C1,58), V(3A,1D,1D,27), V(27,9E,9E,B9), \
    V(D9,E1,E1,38), V(EB,F8,F8,13), V(2B,98,98,B3), V(22,11,11,33), \
    V(D2,69,69,BB), V(A9,D9,D9,70), V(07,8E,8E,89), V(33,94,94,A7), \
    V(2D,9B,9B,B6), V(3C,1E,1E,22), V(15,87,87,92), V(C9,E9,E9,20), \
    V(87,CE,CE,49), V(AA,55,55,FF), V(50,28,28,78), V(A5,DF,DF,7A), \
    V(03,8C,8C,8F), V(59,A1,A1,F8), V(09,89,89,80), V(1A,0D,0D,17), \
    V(65,BF,BF,DA), V(D7,E6,E6,31), V(84,42,42,C6), V(D0,68,68,B8), \
    V(82,41,41,C3), V(29,99,99,B0), V(5A,2D,2D,77), V(1E,0F,0F,11), \
    V(7B,B0,B0,CB), V(A8,54,54,FC), V(6D,BB,BB,D6), V(2C,16,16,3A)

/* #define V(a,b,c,d) 0x##a##b##c##d */
#define V(a,b,c,d) 0x##d##c##b##a
static uint32_t FT0_[256] = { FT };
#undef V

/* #define V(a,b,c,d) 0x##d##a##b##c */
#define V(a,b,c,d) 0x##c##b##a##d
static uint32_t FT1_[256] = { FT };
#undef V

/* #define V(a,b,c,d) 0x##c##d##a##b */
#define V(a,b,c,d) 0x##b##a##d##c
static uint32_t FT2_[256] = { FT };
#undef V

/* #define V(a,b,c,d) 0x##b##c##d##a */
#define V(a,b,c,d) 0x##a##d##c##b
static uint32_t FT3_[256] = { FT };
#undef V

#undef FT


/* reverse S-box */

#define RSbData                                         \
    {                                                   \
      0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,   \
      0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,   \
      0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,   \
      0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,   \
      0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,   \
      0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,   \
      0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,   \
      0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,   \
      0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,   \
      0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,   \
      0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,   \
      0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,   \
      0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,   \
      0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,   \
      0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,   \
      0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,   \
      0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,   \
      0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,   \
      0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,   \
      0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,   \
      0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,   \
      0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,   \
      0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,   \
      0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,   \
      0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,   \
      0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,   \
      0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,   \
      0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,   \
      0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,   \
      0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,   \
      0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,   \
      0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D    \
    }


static uint32_t RSb__A[256] = RSbData;
static uint32_t RSb__B[256] = RSbData;
#undef RSbData


/* reverse table */

#define RT \
\
    V(51,F4,A7,50), V(7E,41,65,53), V(1A,17,A4,C3), V(3A,27,5E,96), \
    V(3B,AB,6B,CB), V(1F,9D,45,F1), V(AC,FA,58,AB), V(4B,E3,03,93), \
    V(20,30,FA,55), V(AD,76,6D,F6), V(88,CC,76,91), V(F5,02,4C,25), \
    V(4F,E5,D7,FC), V(C5,2A,CB,D7), V(26,35,44,80), V(B5,62,A3,8F), \
    V(DE,B1,5A,49), V(25,BA,1B,67), V(45,EA,0E,98), V(5D,FE,C0,E1), \
    V(C3,2F,75,02), V(81,4C,F0,12), V(8D,46,97,A3), V(6B,D3,F9,C6), \
    V(03,8F,5F,E7), V(15,92,9C,95), V(BF,6D,7A,EB), V(95,52,59,DA), \
    V(D4,BE,83,2D), V(58,74,21,D3), V(49,E0,69,29), V(8E,C9,C8,44), \
    V(75,C2,89,6A), V(F4,8E,79,78), V(99,58,3E,6B), V(27,B9,71,DD), \
    V(BE,E1,4F,B6), V(F0,88,AD,17), V(C9,20,AC,66), V(7D,CE,3A,B4), \
    V(63,DF,4A,18), V(E5,1A,31,82), V(97,51,33,60), V(62,53,7F,45), \
    V(B1,64,77,E0), V(BB,6B,AE,84), V(FE,81,A0,1C), V(F9,08,2B,94), \
    V(70,48,68,58), V(8F,45,FD,19), V(94,DE,6C,87), V(52,7B,F8,B7), \
    V(AB,73,D3,23), V(72,4B,02,E2), V(E3,1F,8F,57), V(66,55,AB,2A), \
    V(B2,EB,28,07), V(2F,B5,C2,03), V(86,C5,7B,9A), V(D3,37,08,A5), \
    V(30,28,87,F2), V(23,BF,A5,B2), V(02,03,6A,BA), V(ED,16,82,5C), \
    V(8A,CF,1C,2B), V(A7,79,B4,92), V(F3,07,F2,F0), V(4E,69,E2,A1), \
    V(65,DA,F4,CD), V(06,05,BE,D5), V(D1,34,62,1F), V(C4,A6,FE,8A), \
    V(34,2E,53,9D), V(A2,F3,55,A0), V(05,8A,E1,32), V(A4,F6,EB,75), \
    V(0B,83,EC,39), V(40,60,EF,AA), V(5E,71,9F,06), V(BD,6E,10,51), \
    V(3E,21,8A,F9), V(96,DD,06,3D), V(DD,3E,05,AE), V(4D,E6,BD,46), \
    V(91,54,8D,B5), V(71,C4,5D,05), V(04,06,D4,6F), V(60,50,15,FF), \
    V(19,98,FB,24), V(D6,BD,E9,97), V(89,40,43,CC), V(67,D9,9E,77), \
    V(B0,E8,42,BD), V(07,89,8B,88), V(E7,19,5B,38), V(79,C8,EE,DB), \
    V(A1,7C,0A,47), V(7C,42,0F,E9), V(F8,84,1E,C9), V(00,00,00,00), \
    V(09,80,86,83), V(32,2B,ED,48), V(1E,11,70,AC), V(6C,5A,72,4E), \
    V(FD,0E,FF,FB), V(0F,85,38,56), V(3D,AE,D5,1E), V(36,2D,39,27), \
    V(0A,0F,D9,64), V(68,5C,A6,21), V(9B,5B,54,D1), V(24,36,2E,3A), \
    V(0C,0A,67,B1), V(93,57,E7,0F), V(B4,EE,96,D2), V(1B,9B,91,9E), \
    V(80,C0,C5,4F), V(61,DC,20,A2), V(5A,77,4B,69), V(1C,12,1A,16), \
    V(E2,93,BA,0A), V(C0,A0,2A,E5), V(3C,22,E0,43), V(12,1B,17,1D), \
    V(0E,09,0D,0B), V(F2,8B,C7,AD), V(2D,B6,A8,B9), V(14,1E,A9,C8), \
    V(57,F1,19,85), V(AF,75,07,4C), V(EE,99,DD,BB), V(A3,7F,60,FD), \
    V(F7,01,26,9F), V(5C,72,F5,BC), V(44,66,3B,C5), V(5B,FB,7E,34), \
    V(8B,43,29,76), V(CB,23,C6,DC), V(B6,ED,FC,68), V(B8,E4,F1,63), \
    V(D7,31,DC,CA), V(42,63,85,10), V(13,97,22,40), V(84,C6,11,20), \
    V(85,4A,24,7D), V(D2,BB,3D,F8), V(AE,F9,32,11), V(C7,29,A1,6D), \
    V(1D,9E,2F,4B), V(DC,B2,30,F3), V(0D,86,52,EC), V(77,C1,E3,D0), \
    V(2B,B3,16,6C), V(A9,70,B9,99), V(11,94,48,FA), V(47,E9,64,22), \
    V(A8,FC,8C,C4), V(A0,F0,3F,1A), V(56,7D,2C,D8), V(22,33,90,EF), \
    V(87,49,4E,C7), V(D9,38,D1,C1), V(8C,CA,A2,FE), V(98,D4,0B,36), \
    V(A6,F5,81,CF), V(A5,7A,DE,28), V(DA,B7,8E,26), V(3F,AD,BF,A4), \
    V(2C,3A,9D,E4), V(50,78,92,0D), V(6A,5F,CC,9B), V(54,7E,46,62), \
    V(F6,8D,13,C2), V(90,D8,B8,E8), V(2E,39,F7,5E), V(82,C3,AF,F5), \
    V(9F,5D,80,BE), V(69,D0,93,7C), V(6F,D5,2D,A9), V(CF,25,12,B3), \
    V(C8,AC,99,3B), V(10,18,7D,A7), V(E8,9C,63,6E), V(DB,3B,BB,7B), \
    V(CD,26,78,09), V(6E,59,18,F4), V(EC,9A,B7,01), V(83,4F,9A,A8), \
    V(E6,95,6E,65), V(AA,FF,E6,7E), V(21,BC,CF,08), V(EF,15,E8,E6), \
    V(BA,E7,9B,D9), V(4A,6F,36,CE), V(EA,9F,09,D4), V(29,B0,7C,D6), \
    V(31,A4,B2,AF), V(2A,3F,23,31), V(C6,A5,94,30), V(35,A2,66,C0), \
    V(74,4E,BC,37), V(FC,82,CA,A6), V(E0,90,D0,B0), V(33,A7,D8,15), \
    V(F1,04,98,4A), V(41,EC,DA,F7), V(7F,CD,50,0E), V(17,91,F6,2F), \
    V(76,4D,D6,8D), V(43,EF,B0,4D), V(CC,AA,4D,54), V(E4,96,04,DF), \
    V(9E,D1,B5,E3), V(4C,6A,88,1B), V(C1,2C,1F,B8), V(46,65,51,7F), \
    V(9D,5E,EA,04), V(01,8C,35,5D), V(FA,87,74,73), V(FB,0B,41,2E), \
    V(B3,67,1D,5A), V(92,DB,D2,52), V(E9,10,56,33), V(6D,D6,47,13), \
    V(9A,D7,61,8C), V(37,A1,0C,7A), V(59,F8,14,8E), V(EB,13,3C,89), \
    V(CE,A9,27,EE), V(B7,61,C9,35), V(E1,1C,E5,ED), V(7A,47,B1,3C), \
    V(9C,D2,DF,59), V(55,F2,73,3F), V(18,14,CE,79), V(73,C7,37,BF), \
    V(53,F7,CD,EA), V(5F,FD,AA,5B), V(DF,3D,6F,14), V(78,44,DB,86), \
    V(CA,AF,F3,81), V(B9,68,C4,3E), V(38,24,34,2C), V(C2,A3,40,5F), \
    V(16,1D,C3,72), V(BC,E2,25,0C), V(28,3C,49,8B), V(FF,0D,95,41), \
    V(39,A8,01,71), V(08,0C,B3,DE), V(D8,B4,E4,9C), V(64,56,C1,90), \
    V(7B,CB,84,61), V(D5,32,B6,70), V(48,6C,5C,74), V(D0,B8,57,42)

#define V(a,b,c,d) 0x##a##b##c##d
static uint32_t RT0__A[256] = { RT };
static uint32_t RT0__B[256] = { RT };
#undef V

#undef RT

/* round constants */

static uint32_t RCON[10] =
{
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

int aes_set_key(const uint32_t key[], uint32_t *aes_edrk)
{
    unsigned int i = 0;
    uint32_t rotl_aes_edrk;
      uint32_t aes_edrk_temp8, aes_edrk_temp9, aes_edrk_temp10, aes_edrk_temp11;
      uint32_t aes_edrk_temp12, aes_edrk_temp13, aes_edrk_temp14, aes_edrk_temp15;
      uint32_t temp_lds;
      uint32_t round = 0x00000001;

    aes_edrk_temp8  = (key[0]);
    aes_edrk[0] = aes_edrk_temp8;
    aes_edrk_temp9  = (key[1]);
    aes_edrk[1] = aes_edrk_temp9;
    aes_edrk_temp10 = (key[2]);
    aes_edrk[2] = aes_edrk_temp10;
    aes_edrk_temp11 = (key[3]);
    aes_edrk[3] = aes_edrk_temp11;
    aes_edrk_temp12 = (key[4]);
    aes_edrk[4] = aes_edrk_temp12;
    aes_edrk_temp13 = (key[5]);
    aes_edrk[5] = aes_edrk_temp13;
    aes_edrk_temp14 = (key[6]);
    aes_edrk[6] = aes_edrk_temp14;
    aes_edrk_temp15 = (key[7]);
    aes_edrk[7] = aes_edrk_temp15;

    for( i = 8; i < 64; /* i+=8 */ )
    {
      rotl_aes_edrk   = rotr(aes_edrk_temp15,8);

      temp_lds = f_FSb_32__1(rotl_aes_edrk) ^ f_FSb_32__2( rotl_aes_edrk );

      aes_edrk_temp8 = aes_edrk_temp8 ^ round ^ temp_lds;
      round = round << 1;

      aes_edrk[i++]   = aes_edrk_temp8;
      aes_edrk_temp9  = aes_edrk_temp9  ^ aes_edrk_temp8;
      aes_edrk[i++]   = aes_edrk_temp9;
      aes_edrk_temp10 = aes_edrk_temp10 ^ aes_edrk_temp9;
      aes_edrk[i++]  = aes_edrk_temp10;
      aes_edrk_temp11 = aes_edrk_temp11 ^ aes_edrk_temp10;
      aes_edrk[i++]  = aes_edrk_temp11;

      temp_lds = f_FSb_32__1(aes_edrk_temp11) ^ f_FSb_32__2(aes_edrk_temp11);

      aes_edrk_temp12 = aes_edrk_temp12 ^ temp_lds;
      aes_edrk[i++]  = aes_edrk_temp12;
      aes_edrk_temp13 = aes_edrk_temp13 ^ aes_edrk_temp12;
      aes_edrk[i++]  = aes_edrk_temp13;
      aes_edrk_temp14 = aes_edrk_temp14 ^ aes_edrk_temp13;
      aes_edrk[i++]  = aes_edrk_temp14;
      aes_edrk_temp15 = aes_edrk_temp15 ^ aes_edrk_temp14;
      aes_edrk[i++]  = aes_edrk_temp15;
    }

    return( 0 );
}

void aes_encrypt(const uint32_t input[4], uint32_t output[4], const uint32_t *aes_edrk )
{
  uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;
  unsigned int i = 0, j = 0;
  unsigned int l_aes_nr = 14;

  X0 = (input[i++] ^ aes_edrk[j++]);
  X1 = (input[i++] ^ aes_edrk[j++]);
  X2 = (input[i++] ^ aes_edrk[j++]);
  X3 = (input[i++] ^ aes_edrk[j++]);

/*   printf("%d: 0x%08x 0x%08x 0x%08x 0x%08x\n", 4, X0, X1, X2, X3); */

#define AES_ROUND_NEW(TAB,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)    \
  {                                                     \
    X0  =      FT0[( Y0       ) &0xFF ];                \
    X0 ^=      FT1[( Y1 >>  8 ) &0xFF ];                \
    X0 ^= rotr(FT0[( Y2 >> 16 ) &0xFF ],16);            \
    X0 ^= rotr(FT1[( Y3 >> 24 ) &0xFF ],16);            \
                                                        \
    X1  =      FT0[( Y1       ) &0xFF ];                \
    X1 ^=      FT1[( Y2 >>  8 ) &0xFF ];                \
    X1 ^= rotr(FT0[( Y3 >> 16 ) &0xFF ],16);            \
    X1 ^= rotr(FT1[( Y0 >> 24 ) &0xFF ],16);            \
                                                        \
    X2  =      FT0[( Y2       ) &0xFF ];                \
    X2 ^=      FT1[( Y3 >>  8 ) &0xFF ];                \
    X2 ^= rotr(FT0[( Y0 >> 16 ) &0xFF ],16);            \
    X2 ^= rotr(FT1[( Y1 >> 24 ) &0xFF ],16);            \
                                                        \
    X3  =      FT0[( Y3       ) &0xFF ];                \
    X3 ^=      FT1[( Y0 >>  8 ) &0xFF ];                \
    X3 ^= rotr(FT0[( Y1 >> 16 ) &0xFF ],16);            \
    X3 ^= rotr(FT1[( Y2 >> 24 ) &0xFF ],16);            \
                                                        \
    X0 ^= (TAB[I++]);                                   \
    X1 ^= (TAB[I++]);                                   \
    X2 ^= (TAB[I++]);                                   \
    X3 ^= (TAB[I++]);                                   \
  }
  
  for (i = 4 ; i < (l_aes_nr<<2) ; )
  {
    
    AES_ROUND_NEW(aes_edrk, i, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0=Y0;
    X1=Y1;
    X2=Y2;
    X3=Y3;
  }
  
  /* last round */
  Y0 = (aes_edrk[i]) ^
    ( FSb[( X0       ) &0xFF ]       ) ^
    ( FSb[( X1 >>  8 ) &0xFF ] <<  8 ) ^
    ( FSb[( X2 >> 16 ) &0xFF ] << 16 ) ^
    ( FSb[( X3 >> 24 ) &0xFF ] << 24 );
  
  Y1 = (aes_edrk[1+i]) ^
    ( FSb[( X1       ) &0xFF ]       ) ^
    ( FSb[( X2 >>  8 ) &0xFF ] <<  8 ) ^
    ( FSb[( X3 >> 16 ) &0xFF ] << 16 ) ^
    ( FSb[( X0 >> 24 ) &0xFF ] << 24 );
  
  Y2 = (aes_edrk[2+i]) ^
    ( FSb[( X2       ) &0xFF ]       ) ^
    ( FSb[( X3 >>  8 ) &0xFF ] <<  8 ) ^
    ( FSb[( X0 >> 16 ) &0xFF ] << 16 ) ^
    ( FSb[( X1 >> 24 ) &0xFF ] << 24 );
  
  Y3 = (aes_edrk[3+i]) ^
    ( FSb[( X3       ) &0xFF ]       ) ^
    ( FSb[( X0 >>  8 ) &0xFF ] <<  8 ) ^
    ( FSb[( X1 >> 16 ) &0xFF ] << 16 ) ^
    ( FSb[( X2 >> 24 ) &0xFF ] << 24 );

  output[0] = (Y0);
  output[1] = (Y1);
  output[2] = (Y2);
  output[3] = (Y3);
}

void aes_decrypt(const uint32_t input[4], uint32_t output[4], const uint32_t *aes_edrk )
{
  uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3;
  unsigned int i = 0, j = 0;
  unsigned int l_aes_nr = 14;
  
  i = (l_aes_nr<<2);

  X0 = __builtin_bswap32(input[j++] ^ aes_edrk[i++]);
  X1 = __builtin_bswap32(input[j++] ^ aes_edrk[i++]);
  X2 = __builtin_bswap32(input[j++] ^ aes_edrk[i++]);
  X3 = __builtin_bswap32(input[j++] ^ aes_edrk[i++]);

  
  
#define AES_ROUND_DEC(TAB,I,X0,X1,X2,X3,Y0,Y1,Y2,Y3)                    \
  {									\
    unsigned int tabi = __builtin_bswap32(TAB[I]);                      \
    unsigned int tabiplusun = __builtin_bswap32(TAB[I+1]);              \
    unsigned int tabiplusdeux = __builtin_bswap32(TAB[I+2]);            \
    unsigned int tabiplustrois = __builtin_bswap32(TAB[I+3]);           \
    X0 =       RT0__1[(Y0 >> 24) &0xFF ] ^ KT0__2[(tabi >> 24) & 0xFF]; \
    X0 ^= rotr(RT0__1[(Y3 >> 16) &0xFF ] ^ KT0__2[(tabi >> 16) & 0xFF],8); \
    X0 ^= rotr(RT0__1[(Y2 >>  8) &0xFF ] ^ KT0__2[(tabi >> 8 ) & 0xFF],16); \
    X0 ^= rotr(RT0__1[(Y1      ) &0xFF ] ^ KT0__2[(tabi      ) & 0xFF],24); \
                                                                        \
    X1 =       RT0__2[( Y1 >> 24 ) &0xFF ] ^ KT0__1[(tabiplusun >> 24) & 0xFF]; \
    X1 ^= rotr(RT0__2[( Y0 >> 16 ) &0xFF ] ^ KT0__1[(tabiplusun >> 16) & 0xFF],8); \
    X1 ^= rotr(RT0__2[( Y3 >>  8 ) &0xFF ] ^ KT0__1[(tabiplusun >>  8) & 0xFF],16); \
    X1 ^= rotr(RT0__2[( Y2       ) &0xFF ] ^ KT0__1[(tabiplusun      ) & 0xFF],24); \
                                                                        \
    X2 =       RT0__1[( Y2 >> 24 ) &0xFF ] ^ KT0__2[(tabiplusdeux >> 24) & 0xFF]; \
    X2 ^= rotr(RT0__1[( Y1 >> 16 ) &0xFF ] ^ KT0__2[(tabiplusdeux >> 16) & 0xFF],8); \
    X2 ^= rotr(RT0__1[( Y0 >>  8 ) &0xFF ] ^ KT0__2[(tabiplusdeux >>  8) & 0xFF],16); \
    X2 ^= rotr(RT0__1[( Y3       ) &0xFF ] ^ KT0__2[(tabiplusdeux      ) & 0xFF],24); \
                                                                        \
    X3 =       RT0__2[( Y3 >> 24 ) &0xFF ] ^ KT0__1[(tabiplustrois >> 24) & 0xFF]; \
    X3 ^= rotr(RT0__2[( Y2 >> 16 ) &0xFF ] ^ KT0__1[(tabiplustrois >> 16) & 0xFF],8); \
    X3 ^= rotr(RT0__2[( Y1 >>  8 ) &0xFF ] ^ KT0__1[(tabiplustrois >>  8) & 0xFF],16); \
    X3 ^= rotr(RT0__2[( Y0       ) &0xFF ] ^ KT0__1[(tabiplustrois      ) & 0xFF],24); \
  }
  
  i = (l_aes_nr<<2) - 4;
  do
  {
    AES_ROUND_DEC(aes_edrk, i, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
    X0=Y0;
    X1=Y1;
    X2=Y2;
    X3=Y3;
    i-=4;
  }
  while(i>0);

  /* last round */
  X0 = __builtin_bswap32(aes_edrk[  i]) ^
    ( RSb__1[( Y0 >> 24 ) &0xFF ] << 24 ) ^
    ( RSb__1[( Y3 >> 16 ) &0xFF ] << 16 ) ^
    ( RSb__2[( Y2 >>  8 ) &0xFF ] <<  8 ) ^
    ( RSb__2[( Y1       ) &0xFF ]       );
  
  X1 = __builtin_bswap32(aes_edrk[1+i]) ^
    ( RSb__1[( Y1 >> 24 ) &0xFF ] << 24 ) ^
    ( RSb__1[( Y0 >> 16 ) &0xFF ] << 16 ) ^
    ( RSb__2[( Y3 >>  8 ) &0xFF ] <<  8 ) ^
    ( RSb__2[( Y2       ) &0xFF ]       );
  
  X2 = __builtin_bswap32(aes_edrk[2+i]) ^
    ( RSb__1[( Y2 >> 24 ) &0xFF ] << 24 ) ^
    ( RSb__1[( Y1 >> 16 ) &0xFF ] << 16 ) ^
    ( RSb__2[( Y0 >>  8 ) &0xFF ] <<  8 ) ^
    ( RSb__2[( Y3       ) &0xFF ]       );
  
  X3 = __builtin_bswap32(aes_edrk[3+i]) ^
    ( RSb__1[( Y3 >> 24 ) &0xFF ] << 24 ) ^
    ( RSb__1[( Y2 >> 16 ) &0xFF ] << 16 ) ^
    ( RSb__2[( Y1 >>  8 ) &0xFF ] <<  8 ) ^
    ( RSb__2[( Y0       ) &0xFF ]       );

  output[0] = __builtin_bswap32(X0);
  output[1] = __builtin_bswap32(X1);
  output[2] = __builtin_bswap32(X2);
  output[3] = __builtin_bswap32(X3);
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
static inline void diag1cpu(uint32_t output[4], const uint32_t input[4]) {
  int i,j;
  uint8_t* in = (uint8_t*)input;
  uint8_t* out = (uint8_t*)output;
  for (i = 0 ; i < 4 ; i++) {
    for (j = 0 ; j < 4 ; j++) {
      out[i+((j+3-i)%4)*4] = in[j+(3-i)*4];
    }
  }
}

#endif
