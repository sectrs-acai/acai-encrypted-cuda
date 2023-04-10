#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <mpi.h>

#include "gpu_aes_gcm.h"

#include <openssl/md5.h>

#if 1
#if 0
#define PACKET_SIZE_ED 262144
#define PACKET_SIZE_AD 4096
#define NUM_PACKETS 500
#else
#define PACKET_SIZE_ED 131072
#define PACKET_SIZE_AD 2048
#define NUM_PACKETS 1000
#endif
#else
#define PACKET_SIZE_ED 65536
#define PACKET_SIZE_AD 1024
#define NUM_PACKETS 2000
#endif


int main(int argc, char **argv) {
  uint32_t *keys;
  uint32_t *IV;
  unsigned char* m, *ad, *c;
  unsigned char* control;
  int mpi_rank, mpi_size;
  int ierr, i, j;
  double t0, t1, t2;
  int *count, mycount, *first, myfirst;
  int *sizes, *offsets;
  int leftovers, garbage;

  MPI_Init(&argc, &argv);
  ierr = MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
  if (ierr != MPI_SUCCESS)
    fprintf(stderr, "MPI_Comm_rank failed with %d\n", ierr);
  ierr =  MPI_Comm_size(MPI_COMM_WORLD, &mpi_size);
  if (ierr != MPI_SUCCESS)
    fprintf(stderr, "MPI_Comm_size failed with %d\n", ierr);

  count = (int*)malloc(sizeof(int) * mpi_size);
  first = (int*)malloc(sizeof(int) * mpi_size);
  sizes = (int*)malloc(sizeof(int) * mpi_size);
  offsets = (int*)malloc(sizeof(int) * mpi_size);
  leftovers = NUM_PACKETS;
  for (i = 0 ; i < mpi_size ; i++) {
    count[i] = NUM_PACKETS/mpi_size;
    leftovers -= count[i];
  }
  for (i = 0 ; i < leftovers ; i++)
    count[i%mpi_size]++; // modulo is useless, since leftovers will be < mpi_size-1
  first[0] = 0;
  for (i = 1 ; i < mpi_size ; i++) {
    first[i] = first[i-1] + count[i-1];
  }
  for (i = 0 ; i < mpi_size ; i++) {
    sizes[i] = count[i] * (PACKET_SIZE_ED+16);
  }
  offsets[0] = 0;
  for (i = 1 ; i < mpi_size ; i++) {
    offsets[i] = offsets[i-1] + sizes[i-1];
    
  }

  mycount = count[mpi_rank];
  myfirst = first[mpi_rank];

#ifndef IMPLEMENTATION
#error "IMPLEMENTATION should be defined to crypto_aead_encrypt_cuda/openssl/cryptopp"
  //#define IMPLEMENTATION crypto_aead_encrypt_cuda
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
  printf("%d: I have '%s' and I will do %d at %d\n",
         mpi_rank, TOSTRING(IMPLEMENTATION), mycount, myfirst);

  if (&IMPLEMENTATION == &crypto_aead_encrypt_cuda)
    init_crypto_aead_cuda(16*1024*1024, 8);
  
  keys = (uint32_t*)malloc(8 * sizeof(uint32_t) * mycount);
  IV = (uint32_t*)malloc(4 * sizeof(uint32_t) * mycount);

  srandom(0);
  garbage = 0;
  for (i = 0 ; i < (myfirst+mycount) * 8 ; i++) {
    /* need to call random the proper number of time to get
       the same sequence no matter how many processes */
    if (i < myfirst*8)
      garbage ^= random();
    else
      keys[i-myfirst*8] = random();
  }
  srandom(2);
  for (i = 0 ; i < (myfirst+mycount) * 4 ; i++) {
    if (i < myfirst*4)
      garbage ^= random();
    else
      IV[i-myfirst*4] = random();
  }
  
  m = (unsigned char*)calloc(PACKET_SIZE_ED * mycount, 1);
  ad = (unsigned char*)calloc(PACKET_SIZE_AD * mycount, 1);
  c = (unsigned char*)calloc((PACKET_SIZE_ED+16) * mycount, 1);

  srandom(4);
  for (i = 0 ; i < PACKET_SIZE_ED/4 * (myfirst+mycount) ; i++) {
    if (i < (PACKET_SIZE_ED/4 * myfirst))
      garbage ^= random();
    else
      ((uint32_t*)m)[i-(PACKET_SIZE_ED/4 * myfirst)] = random();
  }
  srandom(6);
  for (i = 0 ; i < PACKET_SIZE_AD/4 * (myfirst+mycount); i++) {
    if (i < (PACKET_SIZE_AD/4 * myfirst))
      garbage ^= random();
    else
      ((uint32_t*)ad)[i-(PACKET_SIZE_AD/4 * myfirst)] = random();
  }

  MPI_Barrier(MPI_COMM_WORLD);
  t0 = wallclock();
  for (i = 0 ; i < mycount ; i++) {
    unsigned long long clen;
    IMPLEMENTATION(c+i*(PACKET_SIZE_ED+16), &clen,
                   m+i*PACKET_SIZE_ED, PACKET_SIZE_ED,
                   ad+i*PACKET_SIZE_AD, PACKET_SIZE_AD,
                   NULL, (unsigned char*)(IV+i*4), (unsigned char*)(keys+i*8));
  }
  t1 = wallclock();
  MPI_Barrier(MPI_COMM_WORLD);
  t2 = wallclock();
  printf("%d: %lf / %lf -> ", mpi_rank, t1-t0, t2-t0);

  free(ad);
  free(m);
  free(IV);
  free(keys);

  if (mpi_rank == 0) {
    control = (unsigned char *)malloc((PACKET_SIZE_ED+16)*NUM_PACKETS);
  } else {
    control = NULL;
  }
  MPI_Gatherv(c,sizes[mpi_rank],MPI_CHAR,
              control,sizes,offsets,MPI_CHAR,
              0,MPI_COMM_WORLD);
  free(c);
  free(count);
  free(first);
  free(sizes);
  free(offsets);
  if (mpi_rank == 0) {
    unsigned char md5[16];
    MD5(control,(PACKET_SIZE_ED+16)*NUM_PACKETS,md5);
    for (i = 0 ; i < 16 ; i++) {
      printf("%02x", md5[i]);
    }
    free(control);
  }
  printf("\n");

  if (&IMPLEMENTATION == &crypto_aead_encrypt_cuda)
    finish_crypto_aead_cuda();

  MPI_Finalize();

  return 0;
}
