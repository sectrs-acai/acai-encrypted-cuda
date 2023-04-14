TARGET=libenccuda.so
CC ?=$(CROSS_COMPILE)gcc
NVCC=nvcc

PREFIX=install
LIBDIR=$(PREFIX)/lib
INCLUDE_DIR=$(PREFIX)/include
SHARE_DIR=$(PREFIX)/share/enc_cuda

GDEV_PREFIX ?= /usr/local

CPPFLAGS+=-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -DOPENSSL_NO_DEPRECATED
CPPFLAGS+=-Iinclude -Ireferences
CFLAGS+=-shared -fPIC -O2 -flto -fvisibility=hidden -fexceptions

LDFLAGS+=-Wl,-z,noexecstack,-z,relro,-z,defs,-z,now

NVCCFLAGS+=-arch sm_21 -cubin -Xcompiler "-march=native -O2"

# for RTLD_NEXT
CPPFLAGS+=-D_GNU_SOURCE

# Libraries:
# - CUDA driver from gdev
# - libcrypto
# - ld.so

CPPFLAGS+=-I$(INCLUDE_DIR) -I$(GDEV_PREFIX)/gdev/include $(shell pkg-config --cflags --libs glib-2.0)
LDFLAGS+=-L$(LIBDIR) -L$(GDEV_PREFIX)/gdev/lib64
LDLIBS+=-ldl -lucuda -lgdev -lcrypto -lglib-2.0

# for LTO
LDFLAGS+=$(CFLAGS)

CUBINS:=references/dolbeau/aes_gpu.cubin
OBJFILES:=src/aes_cpu.o src/enc_cuda.o


.PHONY: all gcc nvcc
all: $(TARGET) $(CUBINS)

gcc: $(TARGET)
nvcc: $(CUBINS)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.cubin: %.cu
	$(NVCC) -o $@ $(NVCCFLAGS) $<

# generate only aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal
DOLBEAU_CONFIG:=references/dolbeau/aes_gpu_impl.h
$(DOLBEAU_CONFIG):
	{ \
		echo "FUNC_AES_FT(ctr,BTB32SRDIAGKEY,0,PRMT,8,nocoal,nocoal,PREROUNDS_DIAGKEY,POSTROUNDS_DIAGKEY)"; \
	} > $@

# generate the config before Dolbeau's AES kernels
references/dolbeau/aes_gpu.cubin: references/dolbeau/aes_gpu.cu references/dolbeau/aes_gpu.h $(DOLBEAU_CONFIG)

.PHONY: install
install: $(TARGET)
	mkdir -p $(LIBDIR) $(INCLUDE_DIR) $(SHARE_DIR)
	cp $(TARGET) $(LIBDIR)
	-cp $(CUBINS) $(SHARE_DIR)
	find "include" -maxdepth 1 -mindepth 1 -print0 | xargs -r0 bash -c "cp -r \$$@ $(INCLUDE_DIR)" _

install-cubins: $(CUBINS)
	mkdir -p $(SHARE_DIR)
	cp $(CUBINS) $(SHARE_DIR)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJFILES)
