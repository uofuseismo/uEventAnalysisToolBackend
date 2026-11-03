#!/bin/bash

# Bash shell script for generating self-signed certs. Run this in a folder, as it
# generates a few files. Large portions of this script were taken from the
# following artcile:
# 
# http://usrportage.de/archives/919-Batch-generating-SSL-certificates.html
# 
# Additional alterations by: Brad Landers
# Date: 2012-01-27
# usage: ./gen_cert.sh example.com

# Script accepts a single argument, the fqdn for the cert
DOMAIN=${1:-seis.utah.edu}
BASENAME=${2:-self-signed-test}
if [ -z "${DOMAIN}" ]; then
  echo "Usage: $(basename $0) <domain>"
  exit 11
fi
if [ -z "${BASENAME}" ]; then
   echo "Usage $(basename $0) <domain> <basename>"
   exit 12
fi

fail_if_error() {
  [ $1 != 0 ] && {
    unset PASSPHRASE
    exit 10
  }
}

# Generate a passphrase
export PASSPHRASE=$(head -c 500 /dev/urandom | tr -dc a-z0-9A-Z | head -c 128; echo)

# Certificate details; replace items in angle brackets with your own info
subj="
C=US
ST=UT
O=UUSS
localityName=Salt Lake City
commonName=${DOMAIN}
organizationalUnitName=UUSS
emailAddress=test-user@utah.edu
"

# Generate the server private key
openssl genrsa -des3 -out ${BASENAME}.key -passout env:PASSPHRASE 4096
fail_if_error $?

# Generate the CSR
openssl req \
    -new \
    -batch \
    -subj "$(echo -n "$subj" | tr "\n" "/")" \
    -key ${BASENAME}.key \
    -out ${BASENAME}.csr \
    -passin env:PASSPHRASE
fail_if_error $?
cp ${BASENAME}.key ${BASENAME}.key.org
fail_if_error $?

# Strip the password so we don't have to type it every time we restart Apache
openssl rsa -in ${BASENAME}.key.org -out ${BASENAME}.key -passin env:PASSPHRASE
fail_if_error $?

# Generate the cert (good for 20 years)
openssl x509 -req -days 7305 -in ${BASENAME}.csr -signkey ${BASENAME}.key -out ${BASENAME}.crt
fail_if_error $?
