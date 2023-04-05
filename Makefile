
TARGET = app
CC = gcc-10
NVCC = nvcc

CPPFLAGS += -I/usr/local/gdev/include -Ireferences
CFLAGS += -g -O2 -march=native
CXXFLAGS += -g -O2 -march=native
NVCCFLAGS += -arch sm_21 -cubin -Xcompiler "$(CXXFLAGS)"

LDFLAGS += $(CFLAGS) -L/usr/local/gdev/lib64
LDLIBS += -lucuda -lgdev -l:libcrypto.so.3


CUBINS := src/kernel.cubin references/dolbeau/aes_gpu.cubin
OBJFILES := src/main.o


.PHONY: all
all: $(TARGET) $(CUBINS)


%.cubin: %.cu
	$(NVCC) -o $@ $(NVCCFLAGS) $<

# generate only aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal
DOLBEAU_CONFIG:=references/dolbeau/aes_gpu_impl.h
$(DOLBEAU_CONFIG):
	{ \
		echo "FUNC_AES_FT(ctr,BTB32SRDIAGKEY,0,PRMT,8,nocoal,nocoal,PREROUNDS_DIAGKEY,POSTROUNDS_DIAGKEY)"; \
	} > references/dolbeau/aes_gpu_impl.h

# generate the config before Dolbeau's AES kernels
references/dolbeau/aes_gpu.cubin: references/dolbeau/aes_gpu.cu references/dolbeau/aes_gpu.h $(DOLBEAU_CONFIG)


$(TARGET): $(OBJFILES)
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJFILES) $(CUBINS) $(DOLBEAU_CONFIG)

.PHONY: run
run: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" ./app


.PHONY: debug
debug: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" gdb ./app
