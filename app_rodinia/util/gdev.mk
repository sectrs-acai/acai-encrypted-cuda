ifeq ($(CC),)
	CC=$(CROSS_COMPILE)gcc
endif
NVCC = nvcc

NVCCFLAGS += -O3 \
	-use_fast_math \
	-arch sm_20 \
	-cubin 

# staging_dir is build directory of buildroot
# run this sourced in buildroot env!
CFLAGS += -I$(CUDA_TOP_DIR)/util \
  	-I$(CUDA_TOP_DIR)/../install/include \
  	-L$(CUDA_TOP_DIR)/../install/lib \
	-I$(STAGING_DIR)/usr/local/gdev/include \
	-L$(STAGING_DIR)/usr/local/gdev/lib64 \
	-lucuda -lgdev \
	-O3 \
	-Wall \

CCFILES += $(CUDA_TOP_DIR)/util/util.c

.PHONY: all clean

all: gcc

nvcc:
	$(NVCC) -o $(EXECUTABLE).cubin $(NVCCFLAGS) $(CUFILES)

gcc:
	$(CC) -o $(EXECUTABLE) $(CCFILES) $(CFLAGS)

clean:
	rm -f $(EXECUTABLE) $(EXECUTABLE).cubin *~
