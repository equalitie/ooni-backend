#!/bin/bash

# Versions of libraries that we need to build a static Tor
OPENSSL_VERSION=1.0.1s
LIBEVENT_VERSION=2.0.21-stable
ZLIB_VERSION=1.2.8
TOR_VERSION=0.2.7.6
ZLIB_SHA256=36658cb768a54c1d4dec43c3116c27ed893e88b02ecfcb44f2166f9c0b7f2a0d

SCRIPT_ROOT=`pwd`

# Package URLS
CURL_URLS="\
http://zlib.net/zlib-$ZLIB_VERSION.tar.gz
https://github.com/downloads/libevent/libevent/libevent-$LIBEVENT_VERSION.tar.gz.asc
https://github.com/downloads/libevent/libevent/libevent-$LIBEVENT_VERSION.tar.gz"

WGET_URLS="\
https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz.asc
https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
https://dist.torproject.org/tor-$TOR_VERSION.tar.gz
https://dist.torproject.org/tor-$TOR_VERSION.tar.gz.asc"

if [ `command -v shasum` ]; then
  SHA256SUM='shasum -a 256'
fi
if [ `command -v sha256sum` ]; then
  SHA256SUM='sha256sum'
fi
if [ ! $SHA256SUM ]; then
  echo "Could not find a suitable command for computing sha256 hash!";
  exit;
fi

# get key for nickm (libevent)
gpg --fingerprint 0xb35bf85bf19489d04e28c33c21194ebb165733ea
if [ $? -ne 0 ]; then
  gpg --keyserver pgp.mit.edu --recv-keys 0xb35bf85bf19489d04e28c33c21194ebb165733ea
  gpg --fingerprint 0xb35bf85bf19489d04e28c33c21194ebb165733ea
  if [ $? -ne 0 ]; then exit ;fi
fi

# get key for Matt Caswell <matt@openssl.org> (openssl)
gpg --fingerprint 0x8657abb260f056b1e5190839d9c4d26d0e604491
if [ $? -ne 0 ]; then
  gpg --keyserver pgp.mit.edu --recv-keys 0x8657abb260f056b1e5190839d9c4d26d0e604491
  gpg --fingerprint 0x8657abb260f056b1e5190839d9c4d26d0e604491
  if [ $? -ne 0 ]; then exit ;fi
fi

# get key for arma (tor) tor
gpg --fingerprint 0xf65ce37f04ba5b360ae6ee17c218525819f78451
if [ $? -ne 0 ]; then
  gpg --keyserver pgp.mit.edu --recv-keys 0xf65ce37f04ba5b360ae6ee17c218525819f78451
  gpg --fingerprint 0xf65ce37f04ba5b360ae6ee17c218525819f78451
  if [ $? -ne 0 ]; then exit ;fi
fi

for URL in $WGET_URLS; do
  wget $URL
done

for URL in $CURL_URLS; do
  curl -LO $URL
done


BUILD=$SCRIPT_ROOT/build
if [ ! -e $BUILD ]; then
  mkdir -p $BUILD
fi

# set up openssl
cd $SCRIPT_ROOT
gpg --verify openssl-$OPENSSL_VERSION.tar.gz.asc openssl-$OPENSSL_VERSION.tar.gz
if [ $? -ne 0 ]; then exit ;fi
tar xfz openssl-$OPENSSL_VERSION.tar.gz
cd openssl-$OPENSSL_VERSION
./config --prefix=$BUILD/openssl-$OPENSSL_VERSION no-shared no-dso && make && make install

# set up libevent
cd $SCRIPT_ROOT
gpg --verify libevent-$LIBEVENT_VERSION.tar.gz.asc libevent-$LIBEVENT_VERSION.tar.gz
if [ $? -ne 0 ]; then exit ;fi
tar xfz libevent-$LIBEVENT_VERSION.tar.gz
cd libevent-$LIBEVENT_VERSION
./configure --prefix=$BUILD/libevent-$LIBEVENT_VERSION -disable-shared --enable-static --with-pic && make && make install

# set up zlib
cd $SCRIPT_ROOT
echo "$ZLIB_SHA256  zlib-$ZLIB_VERSION.tar.gz" | $SHA256SUM -c
if [ $? -ne 0 ]; then exit ;fi

tar xfz zlib-$ZLIB_VERSION.tar.gz
cd zlib-$ZLIB_VERSION
./configure --prefix=$BUILD/zlib-$ZLIB_VERSION --static && make && make install

# set up tor with tor2web mode
cd $SCRIPT_ROOT
gpg --verify tor-$TOR_VERSION.tar.gz.asc tor-$TOR_VERSION.tar.gz
if [ $? -ne 0 ];then exit ;fi
tar xfz tor-$TOR_VERSION.tar.gz
cd tor-$TOR_VERSION
./configure --enable-static-tor --with-libevent-dir=$BUILD/libevent-$LIBEVENT_VERSION --with-openssl-dir=$BUILD/openssl-$OPENSSL_VERSION --with-zlib-dir=$BUILD/zlib-$ZLIB_VERSION --enable-tor2web-mode && make

# copy the binary to $SCRIPT_ROOT
if [ ! -e $SCRIPT_ROOT/tor ]; then
  cp src/or/tor $SCRIPT_ROOT
fi
cd $SCRIPT_ROOT
