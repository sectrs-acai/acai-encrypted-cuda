#pragma once


int aes256_ctr_encrypt_openssl(
  unsigned char *c,int *clen,
  const unsigned char *m, int mlen,
  const unsigned char *npub,
  const unsigned char *k
);


int aes256_ctr_decrypt_openssl(
  unsigned char *m, int *mlen,
  const unsigned char *c, int clen,
  const unsigned char *npub,
  const unsigned char *k
);