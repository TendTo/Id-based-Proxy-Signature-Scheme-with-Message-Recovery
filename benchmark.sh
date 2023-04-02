#!/bin/bash

# Bin directory and binary name taken from Makefile.conf
BIN_DIR=$(sed -n 's/^BIN_DIR\s*:=\s*\(.*\)/\1/p' Makefile.conf)
BINARY=$(sed -n 's/^BINARY\s*:=\s*\(.*\)/\1/p' Makefile.conf)_bench

# Compile the application
make benchmark_compile

# Run the application
./$BIN_DIR/$BINARY "$@"
