
TARGET = cuda_enc_app
CC = gcc-10
NVCC = nvcc

PREFIX=install
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCLUDE_DIR=$(PREFIX)/include
SHARE_DIR=$(PREFIX)/share/enc_cuda_app

CPPFLAGS +=-I$(INCLUDE_DIR) -I/usr/local/gdev/include
CFLAGS += -g -O2 -march=native
CXXFLAGS += -g -O2 -march=native
NVCCFLAGS += -arch sm_21 -cubin -Xcompiler "$(CXXFLAGS)"

LDFLAGS+=-L$(LIBDIR) -L/usr/local/gdev/lib64
LDLIBS+=-lenccuda -lucuda -lgdev


CUBINS := src/kernel.cubin
OBJFILES := src/main.o


.PHONY: all
all: $(TARGET) $(CUBINS)


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
	rm -f $(TARGET) $(OBJFILES) $(CUBINS) $(DOLBEAU_CONFIG)

.PHONY: run
run: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" ./app


.PHONY: debug
debug: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" gdb ./app
