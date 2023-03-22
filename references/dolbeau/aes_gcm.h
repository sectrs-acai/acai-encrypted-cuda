#ifndef _AES_GCM_
#define _AES_GCM_

#ifdef __cplusplus
extern "C" {
#endif

void addmul_ref(unsigned char *a,
                const unsigned char *x,
                const unsigned long long xlen,
                const unsigned char *y);

#if defined(__arm__)
void addmul_neon(unsigned char *a,
                 const unsigned char *x,
                 const unsigned long long xlen,
                 const unsigned char *y);
#define addmul(a,b,c,d)     addmul_neon(a,b,c,d)
#endif

#if defined(__PCLMUL__)
void addmul_pclmul(unsigned char *c,
                   const unsigned char *a, 
		   const unsigned long long xlen,
                   const unsigned char *b);
#define GCM_HAS_UNROLL8
void compute_8power_pclmul(const unsigned char* H,
                    unsigned char* Hn);
void addmul8_pclmul(unsigned char *c,
                    const unsigned char *a, 
                    const unsigned char *bn);
#define GCM_HAS_UNROLL4
void compute_4power_pclmul(const unsigned char* H,
                    unsigned char* Hn);
void addmul4_pclmul(unsigned char *c,
                    const unsigned char *a, 
                    const unsigned char *bn);
#define addmul(a,b,c,d)     addmul_pclmul(a,b,c,d)
#define addmul4(a,b,c)      addmul4_pclmul(a,b,c)
#define addmul8(a,b,c)      addmul8_pclmul(a,b,c)
#define compute_4power(a,b) compute_4power_pclmul(a,b)
#define compute_8power(a,b) compute_8power_pclmul(a,b)
#endif
  
#ifndef addmul
#define addmul(a,b,c,d)      addmul_ref(a,b,c,d)
#endif


void do_gcm(unsigned char *accum, const unsigned char *H,
            const unsigned char *v, unsigned int vlen);
void do_xor_gcm(unsigned char *accum, const unsigned char *H,
                unsigned char *v, const unsigned char *in, unsigned int vlen);
void do_gcm_xor(unsigned char *accum, const unsigned char *H,
                unsigned char *v, const unsigned char *in, unsigned int vlen);

#ifdef __cplusplus
}
#endif
#endif
