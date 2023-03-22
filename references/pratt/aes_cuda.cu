#include <stdio.h>
#include <stdint.h>

#include <cuda.h>
#include <cuda_runtime.h>
#include <driver_functions.h>

#include "CycleTimer.h"
#include "aes_cuda.h"
#include "aes.h"
#include "table.h"




//copy block from inp to outp(1 block per thread)
__device__ void copy_block(uint8_t *inp, uint8_t *out, uint32_t offset){
  //word size traversal
  uint32_t *id = (uint32_t *)inp;
  uint32_t *od = (uint32_t *)out;
  for(int i = 0; i < 4; ++i){
    od[offset/4 + i] = id[offset/4 + i];
  }
}


//XOR round key with block(1 block per thread)
__device__ void add_round_key(uint8_t *block, uint8_t *key, uint32_t offset){
  //word size traversal
  uint32_t *b = (uint32_t *)block;
  uint32_t *k = (uint32_t *)key;
  for(int i = 0; i < 4; ++i){
    b[offset/4 + i] = b[offset/4 + i] ^ k[i];
  }  
}

//substitute block int sbox (1 block per thread)
__device__ void sub_bytes(uint8_t *block, uint32_t offset){
  for(int i = 0; i < 16; ++i){
    block[offset + i] = sbox[block[offset + i]];
  }
}


//mix columns by taking linear combinations in the field (1 block per thread)
__device__ void mix_columns(uint8_t *block, uint32_t offset){
  for(int i = 0; i < 4; ++i){ //iterate over columns
    uint8_t a[4];
    uint8_t b[4]; 
    uint8_t h;
  
    for(int j = 0; j < 4; ++j){
      a[j] = block[offset + 4*i + j];
      h = (uint8_t)((int8_t)a[j] >> 7);
      b[j] = a[j] << 1;
      b[j] ^= 0x1b & h;
    } 

    block[offset + 4*i + 0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    block[offset + 4*i + 1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    block[offset + 4*i + 2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    block[offset + 4*i + 3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; 

  }
}


//shift rows left by 0,1,2,3 bytes respectively (1 block per thread)
__device__ void shift_rows(uint8_t *sblock, uint32_t offset){
  uint8_t tmp;

  uint8_t *block = sblock + offset; 

  //row 0 remains unshifted

  //shift row 1 left by 1
  tmp = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = tmp;

  //shift row 2 letf by 2
  tmp = block[2];
  block[2] = block[10];
  block[10] = tmp;

  tmp = block[6];
  block[6] = block[14];
  block[14] = tmp;

  //shift row 3 left by 3
  tmp = block[3];
  block[3] = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = tmp;

}


//aes 128 encryption with expanded key supplied
//implemented as basic byte algorithm (naive)
//operates on one block per thread
__device__ void encrypt(uint8_t *block, uint8_t *rkey, uint32_t offset){

  add_round_key(block, rkey, offset);

  for(int i = 1; i < 10; ++i){
    sub_bytes(block, offset);
    shift_rows(block, offset);
    mix_columns(block, offset);
    add_round_key(block, rkey + 16*i, offset);
  }

  sub_bytes(block, offset);
  shift_rows(block, offset);
  add_round_key(block, rkey + 160, offset);

}



//aes 128 encryption with expanded key supplied
//implemented using 4 t-tables and sbox
//(watch for endianness) (1 block per thread)
__device__ void encrypt_full_table(uint8_t *block, uint8_t *rkey, uint32_t offset){
  
  uint8_t *b = (block + offset);
  uint32_t *bword = (uint32_t *)(block + offset);

  add_round_key(block, rkey, offset);

  for(int i = 1; i < 10; ++i){

    uint32_t *ckey = (uint32_t *)(rkey + 16*i);

    uint32_t c1 = te0[b[0]]  ^ te1[b[5]]  ^ te2[b[10]] ^ te3[b[15]] ^ ckey[0];
    uint32_t c2 = te0[b[4]]  ^ te1[b[9]]  ^ te2[b[14]] ^ te3[b[3]]  ^ ckey[1];
    uint32_t c3 = te0[b[8]]  ^ te1[b[13]] ^ te2[b[2]]  ^ te3[b[7]]  ^ ckey[2];
    uint32_t c4 = te0[b[12]] ^ te1[b[1]]  ^ te2[b[6]]  ^ te3[b[11]] ^ ckey[3];

    bword[0] = c1;
    bword[1] = c2;
    bword[2] = c3;
    bword[3] = c4;

  }

  sub_bytes(block, offset);
  shift_rows(block, offset);
  add_round_key(block, rkey + 160, offset);
}



//aes 128 encryption with expanded key supplied
//implemented using 1 t-tables (with rotation) and sbox
//1 block per thread
__device__ void encrypt_one_table(uint8_t *block, uint8_t *rkey, uint32_t offset){

  uint8_t *b = (block + offset);
  uint32_t *bword = (uint32_t *)(block + offset);

  add_round_key(block, rkey, offset);

  for(int i = 1; i < 10; ++i){

    uint32_t *ckey = (uint32_t *)(rkey + 16*i);

    uint32_t c1 = te0[b[0]]   ^ (te0[b[5]]<<8 | te0[b[5]]>>24)    ^ (te0[b[10]]<<16 | te0[b[10]]>>16) ^ (te0[b[15]]<<24 | te0[b[15]]>>8) ^ ckey[0];
    uint32_t c2 = te0[b[4]]   ^ (te0[b[9]]<<8 | te0[b[9]]>>24)    ^ (te0[b[14]]<<16 | te0[b[14]]>>16) ^ (te0[b[3]]<<24 | te0[b[3]]>>8)   ^ ckey[1];
    uint32_t c3 = te0[b[8]]   ^ (te0[b[13]]<<8 | te0[b[13]]>>24)  ^ (te0[b[2]]<<16 | te0[b[2]]>>16)   ^ (te0[b[7]]<<24 | te0[b[7]]>>8)   ^ ckey[2];
    uint32_t c4 = te0[b[12]]  ^ (te0[b[1]]<<8 | te0[b[1]]>>24)    ^ (te0[b[6]]<<16 | te0[b[6]]>>16)   ^ (te0[b[11]]<<24 | te0[b[11]]>>8) ^ ckey[3];

    bword[0] = c1;
    bword[1] = c2;
    bword[2] = c3;
    bword[3] = c4;

  }

  sub_bytes(block, offset);
  shift_rows(block, offset);
  add_round_key(block, rkey + 160, offset);

}





//perform aes 128 encryption with either a single table or 4 tables
//offset is the location of the working block in block
//boffset is the column in the working block (0 to 3)
//operates on 1 word per thread
__device__ void encrypt_full_perword(uint8_t *block, uint8_t *rkey, uint32_t offset, uint8_t col){

  uint8_t *b = block + offset;
  uint32_t *bword = (uint32_t *)(block + offset);   //start of the block  
  uint32_t *rwkey = (uint32_t *)rkey;

  //perform add_round_key  performed on single column
  bword[col] = bword[col] ^ rwkey[col];
  for(int i = 1; i < 10; ++i){
    uint32_t *ckey = (uint32_t *)(rkey + 16*i);
    int j = col * 4;


    //multiple t table
   // uint32_t c = te0[b[j]]  ^ te1[b[(j+5)&0xf]]  ^ te2[b[(j+10)&0xf]] ^ te3[b[(j+15)&0xf]] ^ ckey[col];

    //single t table
    
    uint32_t t1 = te0[b[j]];
    uint32_t t2 = te0[b[(j+5)&0xf]];
    uint32_t t3 = te0[b[(j+10)&0xf]];
    uint32_t t4 = te0[b[(j+15)&0xf]];

    uint32_t c = t1 ^ (t2<<8 | t2>>24) ^ (t3<<16 | t3>>16) ^ (t4<<24 | t4>>8) ^ ckey[col];
  
    bword[col] = c;
  }


  //subbytes
  uint8_t v1 = sbox[b[(col*4 + 0)&0xf]];
  uint8_t v2 = sbox[b[(col*4 + 5)&0xf]];
  uint8_t v3 = sbox[b[(col*4 + 10)&0xf]];
  uint8_t v4 = sbox[b[(col*4 + 15)&0xf]];

  //__syncthreads();  should all move together so not a broblem
  
  b[col*4 + 0] = v1;
  b[col*4 + 1] = v2;
  b[col*4 + 2] = v3;
  b[col*4 + 3] = v4;


  //add last round key
  bword[col] ^= rwkey[col + 40];
}


//perform counter mode encryption on block
//operates on a single word per thread with no memory fragmeting
__device__ void ctr_encrypt_perword(uint8_t *block, uint8_t *rkey, uint8_t *rseed, uint8_t *shmem, uint32_t toffset, uint8_t shblk, uint8_t col){
  uint32_t *b = (uint32_t *)block;
  uint32_t *r = (uint32_t *)rseed;
  uint32_t *sh = (uint32_t *)shmem;

  sh[shblk*4 + col] = r[col] + (col == 0)*(toffset / 16);

  //perform encryption
  encrypt_full_perword(shmem, rkey, shblk * 16, col);

  //xor with data
  b[toffset/4 + col] ^= sh[shblk*4 + col];

}



//perform counter mode encryption on block
//naive/ one-table/ or full table mode can be chosen by commenting/uncommenting
//operates on a single block per thread
__device__ void ctr_encrypt(uint8_t *block, uint8_t *rkey, uint8_t *rseed, uint32_t boffset, uint32_t toffset){
  uint32_t *b = (uint32_t *)block;
  uint32_t *r = (uint32_t *)rseed;
  uint32_t addpt[4];
  uint8_t *ctr_block = (uint8_t *)addpt;

  //word size traversal
  for(int i = 0; i < 4; ++i){
    addpt[i] = r[i];
  }

  //add in counter value
  addpt[0] = addpt[0] + toffset/16;
  //encrypt_full_table(ctr_block, rkey, 0);
   encrypt_one_table(ctr_block, rkey, 0);
  //encrypt(ctr_block, rkey, 0);

  //word size traversal
  for(int i = 0; i < 4; ++i){
    b[boffset/4 + i] ^= addpt[i];
  }
}



//basic encryption kernel.  Unused for ctr mode encryption
__global__ void encrypt_k(uint8_t *data, uint8_t *rkey, uint32_t numblock){
  int bindex = blockIdx.x * blockDim.x + threadIdx.x;
  int offset = bindex * 16;
  if(bindex >= numblock) return;
  encrypt_one_table(data, rkey, offset);
}


//Temo test helper
__device__ void inc_block(uint8_t *data, uint32_t offset){  
  //word size traversal
  uint32_t *dat = (uint32_t *)data;
  for(int i = 0; i < 4; ++i){
    dat[offset/4 + i] ^= dat[offset/4 + i];
  }
}



//perfrom counter encryption using a single thread per word with no memory fragmentation
__global__ void ctr_encrypt_nofrag_perword(uint8_t *data, uint8_t *rkey, uint8_t *rseed, uint32_t numblock){
  uint32_t cindex = (blockIdx.y * gridDim.x + blockIdx.x) * blockDim.x + threadIdx.x; //index into column
  uint32_t bindex = cindex/4;
  uint32_t offset = bindex * 16;
  uint8_t shblk = bindex % 16;
  uint8_t col = cindex % 4;

  //memory for performing the encryption
  __shared__ uint32_t shmem[64];

  if(bindex >= numblock)return;

  ctr_encrypt_perword(data, rkey, rseed, (uint8_t *)shmem, offset, shblk, col);

}


//perform ctr encryption with a single thread per block with no memory fragmentation
__global__ void ctr_encrypt_k_nofrag(uint8_t *data, uint8_t *rkey, uint8_t *rseed, uint32_t numblock){
  int bindex = (blockIdx.y * gridDim.x + blockIdx.x) * blockDim.x + threadIdx.x;
  int toffset = bindex * 16;  
  if(bindex >= numblock) return;

  ctr_encrypt(data, rkey, rseed, toffset, toffset);
}


//perform ctr encryption with a single thread per block with memory fragmentation to 
//enable better memory access patterns
__global__ void ctr_encrypt_k_frag(uint8_t *data, uint8_t *rkey, uint8_t *rseed, uint32_t numblock){
  __shared__ uint8_t smem[64 * 20];  
  uint32_t *swmem = (uint32_t *)smem;
  uint32_t *wdata = (uint32_t *)data;

  int bindex = (blockIdx.y * gridDim.x + blockIdx.x) * blockDim.x + threadIdx.x;
  int toffset = bindex * 16;
  int boffset = threadIdx.x * 20; //5 bytes for better memory access patterns
  if(bindex >= numblock) return;

  for(int i = 0; i < 4; ++i){                       //copy block data to memory
    swmem[boffset/4 + i] = wdata[toffset/4 + i];
  }

  ctr_encrypt(smem, rkey, rseed, boffset, toffset);

  for(int i = 0; i < 4; ++i){                       //copy block data to memory
    wdata[toffset/4 + i] = swmem[boffset/4 + i];
  }
}




//handles running the encryption on the gpu
//key expansion is performed off gpu snce it is sequential
void encrypt_cuda_io(const uint8_t *inparray, uint8_t *outarray, uint8_t *key, uint8_t *rseed, uint32_t numblock){
  
  uint32_t num_bytes = numblock * 16;
  
  uint8_t rkey[176];
  
  expand_key(key, rkey);


  uint32_t *ddata;
  uint32_t *drkey;
  uint32_t *drseed;
 
  cudaMalloc(&ddata, sizeof(uint8_t) * num_bytes);
  cudaMalloc(&drkey, sizeof(uint8_t) * 176);
  cudaMalloc(&drseed, sizeof(uint8_t) * 16);

  double out_start_time = CycleTimer::currentSeconds();
  
  cudaMemcpy(ddata, (uint32_t *)inparray, sizeof(uint8_t) * num_bytes, cudaMemcpyHostToDevice);
  cudaMemcpy(drkey, (uint32_t *)rkey, sizeof(uint8_t) * 176, cudaMemcpyHostToDevice);
  cudaMemcpy(drseed, (uint32_t *)rseed, sizeof(uint8_t) * 16, cudaMemcpyHostToDevice);



  uint32_t maxblock = numblock;


  printf("%10.10u, ", numblock);

  dim3 nblock((numblock + 32*64 - 1)/(32*64),128);

//  double avg = 0;
//  for(int i = 0; i < 50; ++i){  

  double in_start_time = CycleTimer::currentSeconds();

  //choose kernel to run
  ctr_encrypt_nofrag_perword<<<nblock, 64>>>((uint8_t *)ddata, (uint8_t *)drkey, (uint8_t *)drseed, numblock);
  //ctr_encrypt_k_nofrag<<<nblock, 64>>>((uint8_t *)ddata, (uint8_t *)drkey, (uint8_t *)drseed, numblock);
  //ctr_encrypt_k_frag<<<nblock, 64>>>((uint8_t *)ddata, (uint8_t *)drkey, (uint8_t *)drseed, numblock);


  cudaThreadSynchronize();
  
  double in_end_time = CycleTimer::currentSeconds();
  double in_duration = in_end_time - in_start_time;

//  avg += in_duration * 1000.0;
  printf("%.3f, ", in_duration * 1000.0);
  fflush(stdout);
 // }
  

  printf("\n");
 // printf("%.3f,\n", avg/50.0);
  





  cudaMemcpy(outarray, ddata, sizeof(uint8_t) * num_bytes, cudaMemcpyDeviceToHost);

  double out_end_time = CycleTimer::currentSeconds();

  //check for errors
  cudaError_t errCode = cudaPeekAtLastError();
  if(errCode != cudaSuccess){
    fprintf(stderr, "WARNING: A CUDA error occured: code=%d, %s\n", errCode, cudaGetErrorString(errCode));
  }

  double out_duration = out_end_time - out_start_time;
  //printf("GPU Overall Out Time: %.3f ms\n\n", 1000.0 * out_duration);

  cudaFree(ddata);
  cudaFree(drkey);
  cudaFree(drseed);

}







/*


void encrypt_cuda(uint8_t *data, uint8_t *key, uint8_t *rseed, uint32_t numblock){
  
  uint32_t num_bytes = numblock * 16;
  
  uint8_t rkey[176];
  
  expand_key(key, rkey);


  uint32_t *ddata;
  uint32_t *drkey;
  uint32_t *drseed;
 
  cudaMalloc(&ddata, sizeof(uint8_t) * num_bytes);
  cudaMalloc(&drkey, sizeof(uint8_t) * 176);
  cudaMalloc(&drseed, sizeof(uint8_t) * 16);

  double out_start_time = CycleTimer::currentSeconds();
  
  cudaMemcpy(ddata, (uint32_t *)data, sizeof(uint8_t) * num_bytes, cudaMemcpyHostToDevice);
  cudaMemcpy(drkey, (uint32_t *)rkey, sizeof(uint8_t) * 176, cudaMemcpyHostToDevice);
  cudaMemcpy(drseed, (uint32_t *)rseed, sizeof(uint8_t) * 16, cudaMemcpyHostToDevice);

  double in_start_time = CycleTimer::currentSeconds();

  ctr_encrypt_k<<<(numblock + 31)/32, 32>>>((uint8_t *)ddata, (uint8_t *)drkey, (uint8_t *)drseed, numblock);
  cudaThreadSynchronize();
  
  double in_end_time = CycleTimer::currentSeconds();

  cudaMemcpy(data, ddata, sizeof(uint8_t) * num_bytes, cudaMemcpyDeviceToHost);

  double out_end_time = CycleTimer::currentSeconds();

  //check for errors
  cudaError_t errCode = cudaPeekAtLastError();
  if(errCode != cudaSuccess){
    fprintf(stderr, "WARNING: A CUDA error occured: code=%d, %s\n", errCode, cudaGetErrorString(errCode));
  }

  double in_duration = in_end_time - in_start_time;
  double out_duration = out_end_time - out_start_time;
  printf("GPU Overall In  Time: %.3f ms\n", 1000.0 * in_duration);
  printf("GPU Overall Out Time: %.3f ms\n\n", 1000.0 * out_duration);

  cudaFree(ddata);
  cudaFree(drseed);
  cudaFree(drkey);

}
*/

//OLD STUFF TO SAVE


/*
__global__ void encrypt_k_io(uint8_t *inpblock, uint8_t *outblock, uint8_t *rkey, uint32_t numblock){

  int bindex = blockIdx.x * blockDim.x + threadIdx.x;
  int offset = bindex * 16;

  if(bindex >= numblock) return;

  copy_block(inpblock, outblock, offset);

  encrypt_one_table(outblock, rkey, offset);

}


__global__ void ctr_encrypt_k_io(uint8_t *inpblock, uint8_t *outblock, uint8_t *rkey, uint8_t *rseed, uint32_t numblock){

  int bindex = blockIdx.x * blockDim.x + threadIdx.x;
  int offset = bindex * 16;

  if(bindex >= numblock) return;

  copy_block(inpblock, outblock, offset);

  ctr_encrypt(outblock, rkey, rseed, offset);

}
*/
