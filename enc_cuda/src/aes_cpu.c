#include "aes_cpu.h"
#include "helpers.h"
#include "cca_benchmark.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>



/* AES-256-CTR mode encryption. */
int aes256_ctr_encrypt_openssl(
  unsigned char *c,int *clen,
  const unsigned char *m, int mlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
	int ret = EXIT_FAILURE;
    CCA_MARKER_CPU_ENC;

	DEBUG_PRINTF("aes256_ctr_encrypt_openssl\n");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER const *cipher = EVP_aes_256_ctr();
    if (ctx == NULL || cipher == NULL)
        goto openssl_err;

	if(EVP_EncryptInit_ex(ctx, cipher, NULL, k, npub) != 1)
		goto openssl_err;
	
	// get/set params if necessary, eg IVLEN 
  	
	// no AD yet
	// if (EVP_EncryptUpdate(ctx, 0, &outlen, ad,adlen) != 1) goto err;
	
	// encrypt m into ciphertext c
	if (EVP_EncryptUpdate(ctx, c, clen, m, mlen) != 1)
		goto openssl_err;
	
	// add trailing padding
	if (EVP_EncryptFinal_ex(ctx, c, clen) != 1)
		goto openssl_err; 

	ret = EXIT_SUCCESS;
	goto cleanup;

openssl_err:
	ERR_print_errors_fp(stderr);
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes256_ctr_decrypt_openssl(
  unsigned char *m, int *mlen,
  const unsigned char *c, int clen,
  const unsigned char *npub,
  const unsigned char *k
)
{
	int ret = EXIT_FAILURE;
    CCA_MARKER_CPU_DEC;


	DEBUG_PRINTF("aes256_ctr_decrypt_openssl\n");


	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER const *cipher = EVP_aes_256_ctr();
    if (ctx == NULL || cipher == NULL)
        goto openssl_err;

	if(EVP_DecryptInit_ex(ctx, cipher, NULL, k, npub) != 1)
		goto openssl_err;

	// get/set params if necessary, eg IVLEN and TAG
	
	// encrypt m into ciphertext c
  	if (EVP_DecryptUpdate(ctx, m, mlen, c, clen) != 1)
		goto openssl_err; 
	
	// add trailing padding
	if (EVP_DecryptFinal_ex(ctx, m, mlen) != 1)
		goto openssl_err; 

	ret = EXIT_SUCCESS;
	goto cleanup;

openssl_err:
	ERR_print_errors_fp(stderr);
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
