#ifndef _GPU_AES_GCM_H_
#define _GPU_AES_GCM_H_

#include "aes_common.h"

#ifdef __cplusplus
extern "C" {
#endif

  /* openssl */
int crypto_aead_encrypt_openssl(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
  );
int crypto_aead_decrypt_openssl(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
  );

  /* crypto++ */
int crypto_aead_encrypt_cryptopp(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
  );
int crypto_aead_decrypt_cryptopp(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
  );

  /* hybrid code CUDA + NEON */
#ifndef GCM_CUDA_MAX_SIZE
#define GCM_CUDA_MAX_SIZE (128*1024*1024) /* must be a multiple of 4096 */
#endif
int crypto_aead_encrypt_cuda(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
  );
int crypto_aead_decrypt_cuda(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
  );
void init_crypto_aead_cuda(const size_t SIZE, const int maxb);
void finish_crypto_aead_cuda(void);

#ifdef __cplusplus
}
#endif

#endif
