# Id based Proxy Signature Scheme with Message Recovery

[![Deploy CI](https://github.com/TendTo/Id-based-Proxy-Signature-Scheme-with-Message-Recovery/actions/workflows/deploy.yml/badge.svg)](https://github.com/TendTo/Id-based-Proxy-Signature-Scheme-with-Message-Recovery/actions/workflows/deploy.yml)

This is a prototype implementation of the Id based Proxy Signature Scheme with Message Recovery as described in the [paper](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery).  
The implementation is written in [c](<https://en.wikipedia.org/wiki/C_(programming_language)>) and uses the [PBC](https://crypto.stanford.edu/pbc/) and [Nettle](http://www.lysator.liu.se/~nisse/nettle/) libraries, with the help of some utilities provided by the professor [Mario di Raimondo](https://diraimondo.dmi.unict.it/).

> **Warning**  
> This project is a prototype implementation of the scheme described in the paper made by a student.
> It is not meant to be used in production environments.
> The code is provided as is, without any warranty.
> There is no guarantee that it is secure or that it will work as expected.
> If you find any bugs or vulnerabilities, feel free to open an issue.

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

For the full documentation about building, see the [Build](docs/Build.md) page.

To build the project, you need to have the PBC library installed.
Then, you can build the project by running the following command:

```shell
make compile
```

Once it has been compiled, the project can be run by executing the following command:

```shell
./run.sh <params>
```

## Usage

After the compilation, an executable will be created in the `bin` directory.  
You can run it directly or use the `run.sh` script, which will keep checking for changes in the source files and recompile the project if needed.  
To see the whole scheme in action, with all its steps, you use the `workflow.sh` script.

```shell
./run.sh <operation> [options]
```

```shell
# Generate the system parameters and store them in the provided file
./run.sh setup -o setup.txt
```

```shell
# Generate the keys associated with the provided identities
./run.sh keygen "$(<setup.txt)" user_id [... user_id] -o keys.txt
```

```shell
# Generate the delegation from 'from_user' to 'to_user' using the private key of 'from_user' in the form [x, y] obtained from the keygen operation
./run.sh delegate "$(<setup.txt)" "[x, y]" from_user to_user -o delegation.bin
```

```shell
# Verifies that the delegation is actually from 'from_user' to 'to_user' by providing the path to the file storing it
./run.sh del_verify "$(<setup.txt)" delegation.bin
```

```shell
# Generate the signature key. It will be used by the delegated user to sign a message on behalf of the delegator
./run.sh pk_gen "$(<setup.txt)" "[x, y]" delegation.bin -o p_sig.txt
```

```shell
# Sign a message on behalf of the delegator
./run.sh p_sign "$(<setup.txt)" delegation.bin "$(<p_sig.txt)" message -o signature.bin
```

```shell
# Verify the signature
./run.sh sign_verify "$(<setup.txt)" delegation.bin signature.bin
```

## Testing

The project uses the [Check](https://libcheck.github.io/check/index.html) library for unit testing.

To run the tests, you need to have the Check library installed.
Then, you can run the tests by executing the following command:

```shell
make test
```

## Benchmarks

The implementation provided by this project has been benchmarked to evaluate its performance.
The full results can be seen in the [Benchmark](docs/Benchmark.md) page.

## Documentation

For more information regarding the cryptographic primitives used in this project, please refer to the original papers.  
A slightly more in depth explanation can be found in the [Paper](docs/Paper.md) page.

## FAQ

If you have any questions, please refer to the [FAQ](docs/FAQ.md) page.
If you can't find the answer to your question, feel free to open an issue.

## References

- [ID-based proxy signature scheme with message recovery](https://www.sciencedirect.com/science/article/abs/pii/S0164121211002159)
- [An Improved ID-based Proxy Signature Scheme with Message Recovery](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery)
- [PBC](https://crypto.stanford.edu/pbc/)
- [Nettle](https://www.lysator.liu.se/~nisse/nettle/)
- [Mario di Raimondo](https://diraimondo.dmi.unict.it/)
- [Crypto Engineering](https://diraimondo.dmi.unict.it/teaching/crypto/)
- [c-project-template](https://github.com/tiborsimon/c-project-template)
