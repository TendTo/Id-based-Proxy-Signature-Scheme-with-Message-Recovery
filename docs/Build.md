# Build

The build process can be configured by editing the variables in the `Makefile.conf` file.

To build the project, you need to have the PBC library installed.
Then, you can build the project by running the following command:

```shell
make compile
```

Once it has been compiled, the project can be run by executing the following command:

```shell
./run.sh <params>
```

For a more options, use the make command:

```shell
---------------------------------------------------------------------
 Improved ID-based Proxy Signature Scheme with Message Recovery 0.0.1
---------------------------------------------------------------------
 make [help]     - Prints out this help message.
 make compile    - Compiles the project.
 make run        - Compiles and runs the project.
 make test       - Compiles the whole test suite and runs it.
 make benchmarks - Compiles the whole benchmark suite and runs it.
 make files      - Prints out the files registered by make.
 make clean      - Cleans up the build directory.
---------------------------------------------------------------------
```

> **Warning**  
> When using either the `make dynamic`, `make static`, `make test` or `make benchmarks` commands, the source code will be compiled with the custom options of the specified target.  
> If the object are already present and the sources have not changed, there may not be any compile step.  
> To make sure the sources are compiled with the right flags, meaning every time the make target changes, it is advised to run the `make clean` command first.

## Dynamic library

The project can be compiled as a dynamic library by running the following command:

```shell
make dynamic
```

This will create a dynamic library in the `bin` directory.  
To use it in your project, either include the headers in the `include` directory or define the functions you intend to use in your code as extern:

```c
// Best solution:
// #include "IdSignature.h"
// If you won't include the headers, you need to define the functions as extern
#define MAX_DIGEST_SIZE 64
#define SHA1_DIGEST_SIZE 20
typedef enum ext_hash_type_t
{
    sha_1,
    sha_256,
    sha_512
} hash_type_t;

extern void hash(uint8_t *digest, const char *message, size_t message_len, hash_type_t hash_type);

int main(int argc, char const *argv[])
{
    uint8_t hash_sha_1[MAX_DIGEST_SIZE];
    hash(hash_sha_1, "Hello World", 11, sha_1);
}
```

When compiling the project, you need to link the library by adding the `-lIdSignature` flag.  
If the library is not in the default library path, you need to add the `-L<path>` flag to the compiler command.

```shell
# Example
gcc -o main main.c -Lbin -lIdSignature
```

If you get the error `error while loading shared libraries: libIdSignature.so: cannot open shared object file: No such file or directory`, you need to tell the linker where to find the library.  
This can be achieved by setting the `LD_LIBRARY_PATH` environment variable:

```shell
# Example
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path to the library>
```

## Static library

The project can be compiled as a static library by running the following command:

```shell
make static
```

This will create a static library in the `bin` directory.  
To use it in your project, either include the headers in the `include` directory or define the functions you intend to use in your code as extern as described in the [dynamic library](#dynamic-library) section.

When compiling the project, you need to link the library by adding the `-lIdSignature` flag as well as all the dependencies with `-lgmp`, `-lpbc` and `-lnettle`.
If the libraries are not in the default library path, you need to add the `-L<path>` flag to the compiler command.

```shell
# Example
gcc -o main main.c -Lbin -lIdSignature -lgmp -lpbc -lnettle
```
