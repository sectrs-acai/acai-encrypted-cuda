# to be compiled every time, as they use compile time definitions
SRCS_CU=aes_cuda.cu gpu_aes_gcm.cu

# can be compiled once as objects
OBJS_C=aes_gcm.o
OBJS_CU=aes_gpu.o
OBJS=$(OBJS_C) $(OBJS_CU)


CC=gcc
CXX=g++
NVCC=nvcc
MPICC=mpicc

GCM_CUDA_CHUNK_SIZE="(2*1024*1024)"


GENCODE=arch=compute_20,code=sm_21
CFLAGS=-march=native -mtune=native -O3 -fomit-frame-pointer 
NVCCFLAGS=-v -g -O3 -std=c++11 -gencode $(GENCODE) -Xcompiler "$(CFLAGS)" -ccbin $(CXX)


all: aes_test aes_test_nocopy aes_hv_nochunk aes_hv_nochunknoxor aes_hv_chunk aes_hv_chunknoxor test_gcm_4 test_gcm_128

GENERATED_HEADERS:=aes_gpu_impl.h aes_cuda_ecb.h aes_cuda_ctr.h
# pattern rule trick
aes_gpu_impl%h aes_cuda_ecb%h aes_cuda_ctr%h: generate_combinations.sh aes_gpu.h
	./$<

%.o: %.cu
	$(NVCC) $(NVCCFLAGS) -c $^ -o $@

test_gcm_4: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -DMAX_SIZE=4194304 aes_gcm.c -o $@

test_gcm_128: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -DMAX_SIZE=134217728 aes_gcm.c -o $@

test_gcm_fpga: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -D__TEST_FPGA__ -DMAX_SIZE=1048576 aes_gcm.c-o $@



gpu_aes_gcm_nochunk.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -c  $< -o $@

gpu_aes_gcm_nochunknoxor.o: gpu_aes_gcm.cu  aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGPU_NOXOR -c $< -o $@

gpu_aes_gcm_chunk.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGCM_CUDA_ENCRYPT_BY_CHUNK -DGCM_CUDA_CHUNK_SIZE=$(GCM_CUDA_CHUNK_SIZE) -c $< -o $@

gpu_aes_gcm_chunknoxor.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGCM_CUDA_ENCRYPT_BY_CHUNK -DGCM_CUDA_CHUNK_SIZE=$(GCM_CUDA_CHUNK_SIZE) -DGPU_NOXOR -c $< -o $@


gpu_aes_gcm_throughput_cuda.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_cuda -c $< -o $@

gpu_aes_gcm_throughput_openssl.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_openssl -c $< -o $@

gpu_aes_gcm_throughput_cryptopp.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_cryptopp -c $< -o $@

TEST=-DTEST_CTR

aes_test: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
	$(NVCC) $(NVCCFLAGS) $(TEST) aes_cuda.cu $(OBJS) -o $@ -lcryptopp -lssl -lcrypto

#aes_test_timing: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
#	$(NVCC) $(NVCCFLAGS) $(TEST) -DDO_TIMING_IN_GPU aes_cuda.cu $(OBJS) -o $@ -lcryptopp -lssl -lcrypto

aes_test_nocopy: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
	$(NVCC) $(NVCCFLAGS) $(TEST) aes_cuda.cu $(OBJS) -o $@ -DNOCOPY -lcryptopp -lssl -lcrypto

aes_hv_nochunk: gpu_aes_gcm_highvolume.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto

aes_hv_nochunknoxor: gpu_aes_gcm_highvolume.o gpu_aes_gcm_nochunknoxor.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto

aes_hv_chunk: gpu_aes_gcm_highvolume.o gpu_aes_gcm_chunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto

aes_hv_chunknoxor: gpu_aes_gcm_highvolume.o gpu_aes_gcm_chunknoxor.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto

aes_tp_cuda_nochunk: gpu_aes_gcm_throughput_cuda.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto -lmpi

aes_tp_openssl: gpu_aes_gcm_throughput_openssl.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto -lmpi

aes_tp_cryptopp: gpu_aes_gcm_throughput_cryptopp.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcryptopp -lssl -lcrypto -lmpi

clean:
	rm -f $(GENERATED_HEADERS) aes_test aes_test_nocopy aes_hv_nochunk aes_hv_nochunknoxor aes_hv_chunk aes_hv_chunknoxor *.o aes_gcm_gpu.aux aes_gcm_gpu.bbl aes_gcm_gpu.blg aes_gcm_gpu.log aes_gcm_gpu.out aes_gcm_gpu.pdf test_gcm_4 test_gcm_128 test_gcm_fpga

