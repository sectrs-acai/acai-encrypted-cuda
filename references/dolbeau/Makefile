SRCS_CU=aes_cuda.cu gpu_aes_gcm.cu
SRCS_C=aes_gcm.c
OBJS=$(SRCS_C:.c=.o)

#on ARM, you may wat to try gcc-4.7 & g++-4.7 over 4.8
CC=gcc
CXX=g++

GCM_CUDA_CHUNK_SIZE="(2*1024*1024)"

ARCH=$(shell arch)
HOSTNAME=$(shell hostname)

ifeq ($(ARCH),armv7l)
	CUDA_INSTALL_PATH=/usr/local/cuda-6.5
	GENCODE=arch=compute_32,code=sm_32
	ifeq ($(HOSTNAME),jetsontk1)
		NVCCFLAGS=-g -O3 -gencode $(GENCODE) -Xcompiler -mcpu=cortex-a15 -Xcompiler -O3 -Xcompiler -fomit-frame-pointer -Xcompiler -mfloat-abi=hard -Xcompiler -mfpu=neon -ccbin $(CXX)
		CFLAGS=-O3 -fomit-frame-pointer -mcpu=cortex-a15 -mfloat-abi=hard -mfpu=neon
	endif
        ifeq ($(HOSTNAME),beaglebone)
                NVCCFLAGS=-g -O3 -gencode $(GENCODE) -Xcompiler -mcpu=cortex-a8 -Xcompiler -O3 -Xcompiler -fomit-frame-pointer -Xcompiler -mfloat-abi=hard -Xcompiler -mfpu=neon -ccbin $(CXX) -DGCM_CUDA_MAX_SIZE="(32*1024*1024)"
                CFLAGS=-O3 -fomit-frame-pointer -mcpu=cortex-a8 -mfloat-abi=hard -mfpu=neon -DGCM_CUDA_MAX_SIZE="(32*1024*1024)"
		CFLAGS+=-DDISABLE_CUDA
        endif
        ifeq ($(HOSTNAME),parallella)
                NVCCFLAGS=-g -O3 -gencode $(GENCODE) -Xcompiler -mcpu=cortex-a9 -Xcompiler -O3 -Xcompiler -fomit-frame-pointer -Xcompiler -mfloat-abi=hard -Xcompiler -mfpu=neon -ccbin $(CXX) -DGCM_CUDA_MAX_SIZE="(32*1024*1024)"
                CFLAGS=-O3 -fomit-frame-pointer -mcpu=cortex-a9 -mfloat-abi=hard -mfpu=neon -DGCM_CUDA_MAX_SIZE="(32*1024*1024)"
                CFLAGS+=-DDISABLE_CUDA
        endif
endif

ifeq ($(ARCH),aarch64)
	CUDA_INSTALL_PATH=
	GENCODE=
	NVCCFLAGS=-g -O3 -gencode $(GENCODE) -Xcompiler -mcpu=cortex-a57 -Xcompiler -O3 -Xcompiler -fomit-frame-pointer -ccbin $(CXX)
	CFLAGS=-O3 -fomit-frame-pointer -mcpu=cortex-a57
	CFLAGS+=-DDISABLE_CUDA
endif
ifeq ($(ARCH),x86_64)
	CUDA_INSTALL_PATH=/home/dolbeau/cuda-6.5
	GENCODE=arch=compute_20,code=sm_21
	ifeq ($(HOSTNAME),robin118)
		CUDA_INSTALL_PATH=/opt/cuda/6.5
		GENCODE=arch=compute_35,code=sm_35
#		CC=icc
#		CXX=icpc
	endif
	NVCCFLAGS=-g -O3 -std=c++11 -gencode $(GENCODE) -Xcompiler -march=native -Xcompiler -mtune=native -Xcompiler -O3 -Xcompiler -fomit-frame-pointer -ccbin $(CXX)
	CFLAGS=-march=native -mtune=native -O3 -fomit-frame-pointer 
	ifeq ($(HOSTNAME),skirfir)
		CFLAGS+=-DDISABLE_CUDA
	endif
	ifeq ($(HOSTNAME),h87m-d3h)
		CFLAGS+=-DDISABLE_CUDA
	endif
	ifeq ($(HOSTNAME),robin118)
		CFLAGS+=-I/home_nfs/bdolbeaur/robin118/include -L/home_nfs/bdolbeaur/robin118/lib -Wl,-rpath,/home_nfs/bdolbeaur/robin118/lib
		NVCCFLAGS+=-I/home_nfs/bdolbeaur/robin118/include -L/home_nfs/bdolbeaur/robin118/lib
	endif
endif

NVCC=$(CUDA_INSTALL_PATH)/bin/nvcc
CC=gcc
MPICC=mpicc

all: aes_test aes_test_nocopy aes_hv_nochunk aes_hv_nochunknoxor aes_hv_chunk aes_hv_chunknoxor test_gcm_4 test_gcm_128

aes_gpu_impl.h aes_cuda_ecb.h aes_cuda_ctr.h: generate_combinations.sh aes_gpu.h
	./$<

%.o:%.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

test_gcm_4: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -DMAX_SIZE=4194304 $< -o $@

test_gcm_128: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -DMAX_SIZE=134217728 $< -o $@

test_gcm_fpga: aes_gcm.c aes_gcm.h aes_common.h
	$(CC) $(CFLAGS) -g -DTEST_GCM -D__TEST_FPGA__ -DMAX_SIZE=1048576 $< -o $@

gpu_aes_gcm_nochunk.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

gpu_aes_gcm_nochunknoxor.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGPU_NOXOR -c $< -o $@

gpu_aes_gcm_chunk.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGCM_CUDA_ENCRYPT_BY_CHUNK -DGCM_CUDA_CHUNK_SIZE=$(GCM_CUDA_CHUNK_SIZE) -c $< -o $@

gpu_aes_gcm_chunknoxor.o: gpu_aes_gcm.cu aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h
	$(NVCC) $(NVCCFLAGS) -DGCM_CUDA_ENCRYPT_BY_CHUNK -DGCM_CUDA_CHUNK_SIZE=$(GCM_CUDA_CHUNK_SIZE) -DGPU_NOXOR -c $< -o $@

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

gpu_aes_gcm_throughput_cuda.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_cuda -c $< -o $@

gpu_aes_gcm_throughput_openssl.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_openssl -c $< -o $@

gpu_aes_gcm_throughput_cryptopp.o: gpu_aes_gcm_throughput.c
	$(MPICC) $(CFLAGS) -DIMPLEMENTATION=crypto_aead_encrypt_cryptopp -c $< -o $@

TEST=-DTEST_CTR

aes_test: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
	$(NVCC) $(NVCCFLAGS) $(TEST) aes_cuda.cu $(OBJS) -o $@ -lcrypto++ -lssl -lcrypto

#aes_test_timing: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
#	$(NVCC) $(NVCCFLAGS) $(TEST) -DDO_TIMING_IN_GPU aes_cuda.cu $(OBJS) -o $@ -lcrypto++ -lssl -lcrypto

aes_test_nocopy: aes_cuda.cu $(OBJS) aes_scalar.h aes_gpu.h aes_gpu_impl.h aes_gcm.h aes_common.h gpu_aes_gcm.h aes_cuda_ctr.h aes_cuda_ecb.h
	$(NVCC) $(NVCCFLAGS) $(TEST) aes_cuda.cu $(OBJS) -o $@ -DNOCOPY -lcrypto++ -lssl -lcrypto

aes_hv_nochunk: gpu_aes_gcm_highvolume.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto

aes_hv_nochunknoxor: gpu_aes_gcm_highvolume.o gpu_aes_gcm_nochunknoxor.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto

aes_hv_chunk: gpu_aes_gcm_highvolume.o gpu_aes_gcm_chunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto

aes_hv_chunknoxor: gpu_aes_gcm_highvolume.o gpu_aes_gcm_chunknoxor.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto

aes_tp_cuda_nochunk: gpu_aes_gcm_throughput_cuda.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto -lmpi

aes_tp_openssl: gpu_aes_gcm_throughput_openssl.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto -lmpi

aes_tp_cryptopp: gpu_aes_gcm_throughput_cryptopp.o gpu_aes_gcm_nochunk.o $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ -lcrypto++ -lssl -lcrypto -lmpi

clean:
	rm -f aes_test aes_test_nocopy aes_hv_nochunk aes_hv_nochunknoxor aes_hv_chunk aes_hv_chunknoxor *.o aes_gcm_gpu.aux aes_gcm_gpu.bbl aes_gcm_gpu.blg aes_gcm_gpu.log aes_gcm_gpu.out aes_gcm_gpu.pdf test_gcm_4 test_gcm_128 test_gcm_fpga

