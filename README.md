# Id based Proxy Signature Scheme with Message Recovery

This is a prototype implementation of the Id based Proxy Signature Scheme with Message Recovery as described in the paper [1].
The implementation is written in [c](<https://en.wikipedia.org/wiki/C_(programming_language)>) and uses the [PBC](https://crypto.stanford.edu/pbc/) library, with the help of some utilities provided by the professor [Mario di Raimondo](https://diraimondo.dmi.unict.it/).

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

## Run

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

## References

- [An Improved ID-based Proxy Signature Scheme with Message Recovery](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery)
- [PBC](https://crypto.stanford.edu/pbc/)
- [Mario di Raimondo](https://diraimondo.dmi.unict.it/)
- [Crypto Engineering](https://diraimondo.dmi.unict.it/teaching/crypto/)

[1]: https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery
