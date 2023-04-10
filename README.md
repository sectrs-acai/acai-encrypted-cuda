# Getting started

Setup:

```bash
make -C enc_cuda install PREFIX="$(realpath install)"
make -C app install PREFIX="$(realpath install)"

## OR ##
./install.sh

## OR (no logging) ##
CPPFLAGS=-DNDEBUG ./install.sh
```

Run:

```bash
sudo LD_LIBRARY_PATH="./install/lib:/usr/local/gdev/lib64:/usr/local/lib64" ./install/bin/cuda_enc_app
```

# Content

## "Encrypted CUDA" library

The library `libenccuda` overrides four functions of the CUDA driver API to make memory transfers between host and GPU encrypted with AES-256-CTR:

```C
CUresult cuMemAlloc(CUdeviceptr *dptr, unsigned int bytesize);
CUresult cuMemFree(CUdeviceptr dptr);
CUresult cuMemcpyDtoH(void *dstHost, CUdeviceptr srcDevice, unsigned int ByteCount);
CUresult cuMemcpyHtoD(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);
```

In addition, it exposes a function used to setup the symmetric key, initial counter value, and prepare the GPU for AES encryption:

```
CUresult cuda_enc_setup(char * key, char * iv);
```

See `enc_cuda/enc_cuda.h` for a description of the function.

## Test app

`app` contains an example that simply copies memory to the device, and back to the host.