#!/bin/bash

# Bin directory and binary name taken from Makefile.conf
BIN_DIR=$(sed -n 's/^BIN_DIR\s*:=\s*\(.*\)/\1/p' Makefile.conf)
BINARY=$(sed -n 's/^BINARY\s*:=\s*\(.*\)/\1/p' Makefile.conf)

# Compile the application
make compile

$flags=""
echo "What message do you want to sign?"
read message
echo "What security level do you want to use?"
read sec_level
sec_level="-l $sec_level"
echo "What hash algorithm do you want to use? (sha1, sha256, sha512)"
read hash_type
hash_type="-a $hash_type"
echo "Do you want to use the improved version? (y/n)"
read imp_flag
if [ "$imp_flag" = "y" ]; then
    flags="-i"
fi
echo "Do you want to include precomputation? (y/n)"
read precomp_flag
if [ "$precomp_flag" = "y" ]; then
    flags="$flags -p"

# This script is used to run the whole pipeline
./$BIN_DIR/$BINARY setup -o setup.txt $sec_level $hash_type $flags
./$BIN_DIR/$BINARY keygen "$(<setup.txt)" from_user to_user -o keys.txt $flags
# Read input from user
echo "Enter the sk of 'from_user' found in 'keys.txt', format '[x, y]': "
read from_sk
./$BIN_DIR/$BINARY delegate "$(<setup.txt)" "$from_sk" from_user to_user -o delegation.bin $flags
./$BIN_DIR/$BINARY del_verify "$(<setup.txt)" delegation.bin $flags
# Read input from user
echo "Enter the sk of 'to_user' found in 'keys.txt', format '[x, y]': "
read to_sk
./$BIN_DIR/$BINARY pk_gen "$(<setup.txt)" "$to_sk" delegation.bin -o p_sig.txt $flags
./$BIN_DIR/$BINARY p_sign "$(<setup.txt)" delegation.bin "$(<p_sig.txt)" "$message" -o signature.bin $flags
./$BIN_DIR/$BINARY sign_verify "$(<setup.txt)" delegation.bin signature.bin $flags
