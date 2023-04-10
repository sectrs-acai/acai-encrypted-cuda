#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "gpu_aes_gcm.h"

/* testing support stuff */
typedef int (*incfun)(const int);

typedef struct testseq {
  const char *name;
  int st;
  int en;
  incfun in;
} testseq;

int inc_16M(const int i) { return i + (16*1024*1024); }
int inc_1M(const int i) { return i + (1*1024*1024); }
int double_inc(const int i) { return i*2; }
int double_inc_with_extra(const int i) {
  int j = i;
  if (i % 4096) {
    j -= 2048;
    j *= 2;
    if (j == 0) j = 4096;
  } else {
    j += 2048;
  }
  return j;
}
const int primes_array[] = {
   4001,  4003,  4007,  4013,  4019,  4021,  4027,  4049,  4051,  4057,
   4073,  4079,  4091,  4093,  4099,  4111,  4127,  4129,  4133,  4139,
   4153,  4157,  4159,  4177,  4201,  4211,  4217,  4219,  4229,  4231,
   4241,  4243,  4253,  4259,  4261,  4271,  4273,  4283,  4289,  4297,
   4327,  4337,  4339,  4349,  4357,  4363,  4373,  4391,  4397,  4409,
   4421,  4423,  4441,  4447,  4451,  4457,  4463,  4481,  4483,  4493,
   4507,  4513,  4517,  4519,  4523,  4547,  4549,  4561,  4567,  4583,
   4591,  4597,  4603,  4621,  4637,  4639,  4643,  4649,  4651,  4657,
   4663,  4673,  4679,  4691,  4703,  4721,  4723,  4729,  4733,  4751,
   4759,  4783,  4787,  4789,  4793,  4799,  4801,  4813,  4817,  4831,
   4861,  4871,  4877,  4889,  4903,  4909,  4919,  4931,  4933,  4937,
   4943,  4951,  4957,  4967,  4969,  4973,  4987,  4993,  4999,  5003,
   5009,  5011,  5021,  5023,  5039,  5051,  5059,  5077,  5081,  5087,
   5099,  5101,  5107,  5113,  5119,  5147,  5153,  5167,  5171,  5179,
   5189,  5197,  5209,  5227,  5231,  5233,  5237,  5261,  5273,  5279,
   5281,  5297,  5303,  5309,  5323,  5333,  5347,  5351,  5381,  5387,
   5393,  5399,  5407,  5413,  5417,  5419,  5431,  5437,  5441,  5443,
   5449,  5471,  5477,  5479,  5483,  5501,  5503,  5507,  5519,  5521,
   5527,  5531,  5557,  5563,  5569,  5573,  5581,  5591,  5623,  5639,
   5641,  5647,  5651,  5653,  5657,  5659,  5669,  5683,  5689,  5693,
   5701,  5711,  5717,  5737,  5741,  5743,  5749,  5779,  5783,  5791,
   5801,  5807,  5813,  5821,  5827,  5839,  5843,  5849,  5851,  5857,
   5861,  5867,  5869,  5879,  5881,  5897,  5903,  5923,  5927,  5939,
   5953,  5981,  5987,  6007,  6011,  6029,  6037,  6043,  6047,  6053,
   6067,  6073,  6079,  6089,  6091,  6101,  6113,  6121,  6131,  6133,
   6143,  6151,  6163,  6173,  6197,  6199,  6203,  6211,  6217,  6221,
   6229,  6247,  6257,  6263,  6269,  6271,  6277,  6287,  6299,  6301,
   6311,  6317,  6323,  6329,  6337,  6343,  6353,  6359,  6361,  6367,
   6373,  6379,  6389,  6397,  6421,  6427,  6449,  6451,  6469,  6473,
   6481,  6491,  6521,  6529,  6547,  6551,  6553,  6563,  6569,  6571,
   6577,  6581,  6599,  6607,  6619,  6637,  6653,  6659,  6661,  6673,
   6679,  6689,  6691,  6701,  6703,  6709,  6719,  6733,  6737,  6761,
   6763,  6779,  6781,  6791,  6793,  6803,  6823,  6827,  6829,  6833,
   6841,  6857,  6863,  6869,  6871,  6883,  6899,  6907,  6911,  6917,
   6947,  6949,  6959,  6961,  6967,  6971,  6977,  6983,  6991,  6997,
   7001,  7013,  7019,  7027,  7039,  7043,  7057,  7069,  7079,  7103,
   7109,  7121,  7127,  7129,  7151,  7159,  7177,  7187,  7193,  7207,
   7211,  7213,  7219,  7229,  7237,  7243,  7247,  7253,  7283,  7297,
   7307,  7309,  7321,  7331,  7333,  7349,  7351,  7369,  7393,  7411,
   7417,  7433,  7451,  7457,  7459,  7477,  7481,  7487,  7489,  7499,
   7507,  7517,  7523,  7529,  7537,  7541,  7547,  7549,  7559,  7561,
   7573,  7577,  7583,  7589,  7591,  7603,  7607,  7621,  7639,  7643,
   7649,  7669,  7673,  7681,  7687,  7691,  7699,  7703,  7717,  7723,
   7727,  7741,  7753,  7757,  7759,  7789,  7793,  7817,  7823,  7829,
   7841,  7853,  7867,  7873,  7877,  7879,  7883,  7901,  7907,  7919,
   7927,  7933,  7937,  7949,  7951,  7963,  7993,  8009,  8011,  8017,
   8039,  8053,  8059,  8069,  8081,  8087,  8089,  8093,  8101,  8111,
   8117,  8123,  8147,  8161,  8167,  8171,  8179,  8191,  8209,  8219,
   8221,  8231,  8233,  8237,  8243,  8263,  8269,  8273,  8287,  8291,
   8293,  8297,  8311,  8317,  8329,  8353,  8363,  8369,  8377,  8387,
   8389,  8419,  8423,  8429,  8431,  8443,  8447,  8461,  8467,  8501,
   8513,  8521,  8527,  8537,  8539,  8543,  8563,  8573,  8581,  8597,
   8599,  8609,  8623,  8627,  8629,  8641,  8647,  8663,  8669,  8677,
   8681,  8689,  8693,  8699,  8707,  8713,  8719,  8731,  8737,  8741,
   8747,  8753,  8761,  8779,  8783,  8803,  8807,  8819,  8821,  8831,
   8837,  8839,  8849,  8861,  8863,  8867,  8887,  8893,  8923,  8929,
   8933,  8941,  8951,  8963,  8969,  8971,  8999,  9001,  9007,  9011,
   9013,  9029,  9041,  9043,  9049,  9059,  9067,  9091,  9103,  9109,
   9127,  9133,  9137,  9151,  9157,  9161,  9173,  9181,  9187,  9199,
   9203,  9209,  9221,  9227,  9239,  9241,  9257,  9277,  9281,  9283,
   9293,  9311,  9319,  9323,  9337,  9341,  9343,  9349,  9371,  9377,
   9391,  9397,  9403,  9413,  9419,  9421,  9431,  9433,  9437,  9439,
   9461,  9463,  9467,  9473,  9479,  9491,  9497,  9511,  9521,  9533,
   9539,  9547,  9551,  9587,  9601,  9613,  9619,  9623,  9629,  9631,
   9643,  9649,  9661,  9677,  9679,  9689,  9697,  9719,  9721,  9733,
   9739,  9743,  9749,  9767,  9769,  9781,  9787,  9791,  9803,  9811,
   9817,  9829,  9833,  9839,  9851,  9857,  9859,  9871,  9883,  9887,
   9901,  9907,  9923,  9929,  9931,  9941,  9949,  9967,  9973,  0x7FFFFFFF
};
int next_in_primes_array(const int i) {
  int j;
  for (j = 0 ; primes_array[j] != i ; j++)
    ;
  return primes_array[j+1];
}

const testseq alltestseq[7] = {
  { "linear16M",              16*1024*1024,    GCM_CUDA_MAX_SIZE, &inc_16M },
  { "linear1M",               1*1024*1024,     GCM_CUDA_MAX_SIZE, &inc_1M },
  { "exponential",            4096,            GCM_CUDA_MAX_SIZE, &double_inc },
  { "exponential_with_extra", 4096,            GCM_CUDA_MAX_SIZE, &double_inc_with_extra },
  { "primes_array",           4001 /* pa[0] */,GCM_CUDA_MAX_SIZE, &next_in_primes_array },
  { "maxonly",                GCM_CUDA_MAX_SIZE,GCM_CUDA_MAX_SIZE, &inc_16M },
  { NULL,0,0,NULL }
};
    

int main(int argc, char **argv) {
  uint32_t key[8];
  uint32_t IV[4];
  int i,j,k,start;
  testseq test = alltestseq[2];

  if (argc > 1) {
    for (i = 0 ; alltestseq[i].name != NULL ; i++) {
      if (strcmp(argv[1],alltestseq[i].name) == 0) {
        test = alltestseq[i];
      }
    }
  }
  
  srandom(0);
  for (i = 0 ; i < 8 ; i++) {
    key[i] = random();
  }
  for (i = 0 ; i < 4 ; i++) {
    IV[i] = random();
  }

#ifndef DISABLE_CUDA
  init_crypto_aead_cuda(GCM_CUDA_MAX_SIZE, 16);
#endif

  start = 0;
#ifdef DISABLE_CUDA
  start = 2;
#endif

  for(k=start;k<3;k++) {
    printf("%s\n",k==1?"With AD (same size as AE)" : (k == 2 ? "AD only" : "With no AD"));
    printf("E time [s]\topenssl \tcryptopp\tcuda    \tE speed [MB/s]\topenssl \tcryptopp\tcuda    \t");
    printf("D time [s]\topenssl \tcryptopp\tcuda    \tD speed [MB/s]\topenssl \tcryptopp\tcuda    \n");
//    for (i = 1048576 ; i <= 32*1048576 ; i+= 1048576) {
//    for (i = 4096 ; i <= 128*1048576 ; i*=2) {
//    for (i = 2048 ; i <= 16384; i+=1024) {
//    for (i = 4096 ; i <= 128*1048576 ; (i%4096)?i=(i-2048)*2:i=i+2048) {
    for (i = test.st ; i <= test.en ; i = test.in(i) ) {
      unsigned char *ad;
      unsigned char *m;
      unsigned char *copenssl, *ccryptopp, *ccuda;
      unsigned char *mopenssl, *mcryptopp, *mcuda;
      double t_[10];
      int tc = 0;
      unsigned long long clen;
      unsigned long long mlen;
      int count;
      ad = (unsigned char*)malloc((i+19)&~3);
      m = (unsigned char*)malloc((i+19)&~3);
      copenssl = (unsigned char*)malloc(i+16);
      ccryptopp = (unsigned char*)malloc(i+16);
      ccuda = (unsigned char*)malloc(i+16);
      mopenssl = (unsigned char*)malloc(i);
      mcryptopp = (unsigned char*)malloc(i);
      mcuda = (unsigned char*)malloc(i);
      srandom(1);
      for (j = 0  ; j < (i+19)/4 ; j++) { //extra garbage block at the end
        ((int*)ad)[j] = random();
        ((int*)m)[j] = random();
      }
    
      /* encrypt & decrypt with all three implementations */
      t_[tc++] = wallclock();
      crypto_aead_encrypt_openssl(copenssl  , &clen, m, k<2?i:0, ad, k?i:0, NULL, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();
      crypto_aead_encrypt_cryptopp(ccryptopp, &clen, m, k<2?i:0, ad, k?i:0, NULL, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();
      crypto_aead_encrypt_cuda(ccuda        , &clen, m, k<2?i:0, ad, k?i:0, NULL, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();
      crypto_aead_decrypt_openssl(mopenssl  , &mlen, NULL, copenssl, (k<2?i:0)+16, ad, k?i:0, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();
      crypto_aead_decrypt_cryptopp(mcryptopp, &mlen, NULL, ccryptopp, (k<2?i:0)+16, ad, k?i:0, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();
      crypto_aead_decrypt_cuda(mcuda        , &mlen, NULL, ccuda, (k<2?i:0)+16, ad, k?i:0, (const unsigned char*)IV, (const unsigned char*)key);
      t_[tc++] = wallclock();

      /* check that the results are OK for all three.
         Abort testing if something computes wrongly.
      */
      count = 0;
      for (j = 0 ; j < (k<2?i:0)+16 && count < 10 ; j++) {
        if ((copenssl[j] != ccryptopp[j]) || (copenssl[j] != ccuda[j])) {
          count ++;
          fprintf(stderr, "ENCRYPT ERROR: @%d: 0x%02hhx / 0x%02hhx / 0x%02hhx\n", j, copenssl[j], ccryptopp[j], ccuda[j]);
        }
        if (j < (k<2?i:0)) {
          if ((mopenssl[j] != mcryptopp[j]) || // (mopenssl[j] != mcuda[j]) ||
              (mopenssl[j] != m[j])) {
            count ++;
            fprintf(stderr, "DECRYPT ERROR: @%d: 0x%02hhx / 0x%02hhx / 0x%02hhx\n", j, copenssl[j], ccryptopp[j], ccuda[j]);
          }
        }
      }
      if (count) {
        i = 0x10000000;
	k = 0x10000000;
        goto endloop;
      }

      printf("% 9d\t%lf\t%lf\t%lf\t", i, t_[1]-t_[0], t_[2]-t_[1], t_[3]-t_[2]);
      printf("% 9d\t%lf\t%lf\t%lf\t", i, i/(1000000.*(t_[1]-t_[0])), i/(1000000.*(t_[2]-t_[1])), i/(1000000.*(t_[3]-t_[2])));
      printf("% 9d\t%lf\t%lf\t%lf\t", i, t_[4]-t_[3], t_[5]-t_[4], t_[6]-t_[5]);
      printf("% 9d\t%lf\t%lf\t%lf\n", i, i/(1000000.*(t_[4]-t_[3])), i/(1000000.*(t_[5]-t_[4])), i/(1000000.*(t_[6]-t_[5])));
      fflush(stdout);
    
    endloop:
      free(ad);
      free(m);
      free(copenssl);
      free(ccryptopp);
      free(ccuda);
      free(mopenssl);
      free(mcryptopp);
      free(mcuda);
    }
  }
  
#ifndef DISABLE_CUDA
  finish_crypto_aead_cuda();
#endif
}
