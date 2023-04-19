# Id based Proxy Signature Scheme with Message Recovery

This is a prototype implementation of the Id based Proxy Signature Scheme with Message Recovery as described in the [paper](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery).  
The implementation is written in [c](<https://en.wikipedia.org/wiki/C_(programming_language)>) and uses the [PBC](https://crypto.stanford.edu/pbc/) and [Nettle](http://www.lysator.liu.se/~nisse/nettle/) libraries, with the help of some utilities provided by the professor [Mario di Raimondo](https://diraimondo.dmi.unict.it/).

## Requirements

- [PBC](https://crypto.stanford.edu/pbc/)
- [gmp](https://gmplib.org/)
- [nettle](http://www.lysator.liu.se/~nisse/nettle/)
- [gcc](https://gcc.gnu.org/) o [clang](https://clang.llvm.org/)
- _\[optional\]_ [Make](https://www.gnu.org/software/make/)
- _\[optional\]_ [Check](https://libcheck.github.io/check/index.html)

## Directory Structure

The project is structured as follows:

```shell
.
├── benchmark # contains the benchmarking scripts
├── bin # contains the executables
├── build # contains the object files
├── include # contains the header files
├── lib # contains the PBC and utility libraries
├── src # contains the source files
└── test # contains the test files
```

## Build

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

### Dynamic library

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

### Static library

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

## Usage

After the compilation, an executable will be created in the `bin` directory.  
You can run it directly or use the `run.sh` script, which will keep checking for changes in the source files and recompile the project if needed.

```shell
./run.sh <operation> [options]
```

```shell
# Generate the system parameters and store them in the provided file
./run.sh setup -o setup_file
```

```shell
# Generate the keys associated with the provided identities
./run.sh keygen "$(<setup_file)" user_id [... user_id] -o keys_file
```

```shell
# Generate the delegation from 'from_user' to 'to_user' using the private key of 'from_user' in the form [x, y] obtained from the keygen operation
./run.sh delegate "$(<setup)" "[x, y]" from_user to_user
```

```shell
# Verifies that the delegation is actually from 'from_user' to 'to_user' by providing the values 'r' and 'S' obtained from the delegate operation
./run.sh del_verify "$(<setup)" "[r_x, r_y]" "[s_x, s_y]" from_user to_user
```

## Documentation

For more information regarding the cryptographic primitives used in this project, please refer to the original papers.  
A slightly more in depth explanation can be found in the [docs folder](docs/README.md).

## References

- [ID-based proxy signature scheme with message recovery](https://www.sciencedirect.com/science/article/abs/pii/S0164121211002159)
- [An Improved ID-based Proxy Signature Scheme with Message Recovery](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery)
- [PBC](https://crypto.stanford.edu/pbc/)
- [Mario di Raimondo](https://diraimondo.dmi.unict.it/)
- [Crypto Engineering](https://diraimondo.dmi.unict.it/teaching/crypto/)
