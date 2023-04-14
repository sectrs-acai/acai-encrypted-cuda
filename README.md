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
CUresult cuMemAlloc(CUdeviceptr *dev_ptr, unsigned int bytesize);
CUresult cuMemFree(CUdeviceptr dev_ptr);
CUresult cuMemcpyDtoH(void *dstHost, CUdeviceptr srcDevice, unsigned int ByteCount);
CUresult cuMemcpyHtoD(CUdeviceptr dstDevice, const void *srcHost, unsigned int ByteCount);
```

In addition, it exposes a function used to setup the symmetric key, initial counter value, and prepare the GPU for AES encryption:

```
CUresult cuda_enc_setup(char * key, char * iv);
```

See `enc_cuda/enc_cuda.h` for a description of the function.


The AES routines used are:

- On the host, the OpenSSL AES-CTR functions (libcrypto).
- On the GPU, the AES-CTR functions [implemented by Romain Dolbeau](http://dolbeau.name/dolbeau/crypto/crypto.html) for a [WIP paper](http://www.dolbeau.name/dolbeau/publications/aes_gcm_gpu.pdf). Even though it is a WIP paper, it appears to be the most complete open source implementation of an AES cipher available online.
    + At the time of writing, his webpage seems to be down, but is still available on <archive.org>:
        * [project presentation and code](https://web.archive.org/web/20221127200344/http://dolbeau.name/dolbeau/crypto/crypto.html)
        * [the WIP paper](https://web.archive.org/web/20210813051708/http://www.dolbeau.name/dolbeau/publications/aes_gcm_gpu.pdf)
    + More specifically, I only tried using the function that is reported as most high-performing in the paper (`aes_ctr_cuda_BTB32SRDIAGKEY0_PRMT_8nocoalnocoal`).

## Test app

`app` contains an example that simply copies memory to the device, and back to the host.



# Limitations

- The counter value is NOT incremented between encryptions!!!
- This is not AES-GCM!
- I intended to test a second implementation (in the repo at `enc_cuda/references/burcel`), but currently only tested the AES ciphers from R. Dolbeau. The second implementation is the result of a master thesis.