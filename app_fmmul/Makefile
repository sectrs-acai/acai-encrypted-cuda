
TARGET = cuda_enc_app
CC = $(CROSS_COMPILE)gcc
NVCC = nvcc

PREFIX=../install
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCLUDE_DIR=$(PREFIX)/include
SHARE_DIR=$(PREFIX)/share/enc_cuda_app

GDEV_PREFIX ?= /usr/local

CPPFLAGS +=-I$(INCLUDE_DIR) -I$(GDEV_PREFIX)/gdev/include
CFLAGS += -g -O2
CXXFLAGS += -g -O2
NVCCFLAGS += -arch sm_21 -cubin -Xcompiler "$(CXXFLAGS)"

LDFLAGS+=-L$(LIBDIR) -L$(GDEV_PREFIX)/gdev/lib64
LDLIBS+=-lenccuda -lucuda -lgdev
#LDLIBS+= -lucuda -lgdev
# make sure that libenccuda is loaded BEFORE libucuda and ibgdev,
# as it will look for symbols is the dynamic libraries that follow it

CFLAGS += -DCUDA_ENC

CUBINS := src/kernel.cubin
OBJFILES := src/main.o


.PHONY: all
all: $(TARGET) $(CUBINS)

gcc: $(TARGET)
nvcc: $(CUBINS)


%.cubin: %.cu
	$(NVCC) -o $@ $(NVCCFLAGS) $<


$(TARGET): $(OBJFILES)
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)


.PHONY: install
install: $(TARGET)
	mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJFILES)

.PHONY: run
run: all
	sudo LD_LIBRARY_PATH=$(GDEV_PREFIX)"/gdev/lib64" ./app


.PHONY: debug
debug: all
	sudo LD_LIBRARY_PATH=$(GDEV_PREFIX)"/gdev/lib64" gdb ./app
