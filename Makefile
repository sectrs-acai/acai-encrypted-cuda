
TARGET = app
CC = gcc-10
NVCC = nvcc -arch sm_21 -cubin

CPPFLAGS += -I/usr/local/gdev/include
CFLAGS += -g -O2 -march=native

LDFLAGS += $(CFLAGS) -L/usr/local/gdev/lib64
LDLIBS += -lucuda -lgdev


CUBINS := src/kernel.cubin
OBJFILES := src/main.o


.PHONY: all
all: $(TARGET) $(CUBINS)

%.cubin: %.cu
	$(NVCC) -o $@ $^

$(TARGET): $(OBJFILES)
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJFILES) $(CUBINS)

.PHONY: run
run: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" ./app


.PHONY: debug
debug: all
	sudo LD_LIBRARY_PATH="/usr/local/gdev/lib64" gdb ./app
