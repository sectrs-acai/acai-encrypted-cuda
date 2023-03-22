#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "aes.h"
#include "aes_cuda.h"



//read data from random file
void * file_buf(char *file){

  int fd = open(file, O_RDONLY);
  if(fd < 0){ fprintf(stderr, "Error opening file"); exit(1);}

  struct stat stats;
  if(fstat(fd, &stats) < 0){ fprintf(stderr, "Error opening file"); exit(1);}
  
  void *mem = (uint8_t *)mmap(NULL, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0); 
  if(mem == MAP_FAILED){ fprintf(stderr, "mmap failed"); exit(1);}
  
  return mem;
}
  



int main(void){



  uint8_t key[16] = {0x54,0x68,0x61,0x74,0x73,0x20,0x6d,0x79,0x20,0x4b,0x75,0x6e,0x67,0x20,0x46,0x75};
  uint8_t rseed[16] = {0,5,1,0,0,0,6,0,24,0,0,0,0,0,0,0};

  char dat1[16] = "../1grand.dat";
  const uint8_t *d1 = (const uint8_t *)file_buf(dat1);  





  //TEST ON CPU

  uint32_t size = 1073741824/64;


  uint8_t *output_cpu = (uint8_t *) malloc(sizeof(uint8_t) * size);
  uint8_t *output_gpu = (uint8_t *) malloc(sizeof(uint8_t) * size);

   aes_ctr(d1, size, key, rseed, output_cpu);

  
  //TEST ON GPU

  encrypt_cuda_io(d1, output_gpu, key, rseed, size/16); 



  //Test correctness
  int sum = 0;
  for(uint32_t i = 0; i < size; ++i){
    sum += abs(output_cpu[i] - output_gpu[i]);
    
  }
  printf("Sum = %d  (should be zero if correct)\n", sum);

/*
  for(int i = 0; i < 4; ++i){
    print_block_hex(output_cpu + 16*i);
    print_block_hex(output_gpu + 16*i);
  }

*/

/*
  double stime;
  double cputime;
  double gputime;

  uint32_t off = 0;


  for(int i = 0; i < 5; ++i){
    uint32_t tsize = (size >> i);
    stime = CycleTimer::currentSeconds();
    aes_ctr(d1 + off, tsize, key, rseed, output_cpu);
    cputime = CycleTimer::currentSeconds() - stime;
        
    stime = CycleTimer::currentSeconds();
    encrypt_cuda(d1 + off, output_gpu, key, rseed, tsize/16); 
    gputime = CycleTimer::currentSeconds() - stime;
  
    off += tsize;

    printf(">>>Iteration %d, CPU: %.3f GPU: %.3f Speedup: %.3f\n\n", i, cputime*1000.0, gputime*1000.0, cputime/gputime);

  }
    
  */  

/*

  uint8_t inptext[16] = {0x54,0x77,0x6f,0x20,0x4f,0x6e,0x65,0x20,0x4e,0x69,0x6e,0x65,0x20,0x54,0x77,0x6f};
  uint8_t inptext1[16] = {0x54,0x77,0x6f,0x20,0x4f,0x6e,0x65,0x20,0x4e,0x69,0x6e,0x65,0x20,0x54,0x77,0x6f};
  uint8_t outtext[16];
  uint8_t rstring[16] = {0x54,0x77,0x6f,0x20,0x4f,0x6e,0x65,0x20,0x4e,0x69,0x6e,0x65,0x20,0x54,0x77,0x6f};



  print_block_hex(inptext);
  print_block_hex(key);

  encrypt_cuda(inptext, outtext, key, rseed, 1);

  print_block_hex(outtext);

  printf("\n\n");


  print_block_hex(inptext1);
  print_block_hex(key);
  //encrypt(inptext1, key);
  aes_ctr(inptext1, 16, key, rseed, outtext);
  print_block_hex(outtext);

*/
/*
  for(int i = 0; i < 256/8; ++i){
    for(int j = 0; j < 8; ++j){
      printf("0x%8.8x, ", __builtin_bswap32(te3[i*8 + j]));
    }
    printf("\n");
  }
 */





}

