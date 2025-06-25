#!/usr/bin/bash

cd elfutils

mkdir out
mkdir out/aarch64
mkdir out/amd64

CC=clang ./configure --prefix $(realpath ./out/aarch64) --host="aarch64" --enable-maintainer-mode --disable-dependency-tracking
make clean
make -j8
make install -j8

CC=clang ./configure --prefix $(realpath ./out/amd64) --enable-maintainer-mode --disable-dependency-tracking
make clean
make -j8
make install -j8


cd openssl

./Configure linux-aarch64 --prefix=$(realpath out/aarch64) --openssldir=$(realpath out/aarch64) -g -O2 --cross-compile-prefix= CC=aarch64-linux-android33-clang
make -j8
make install -j8

./Configure linux-x86_64 --prefix=$(realpath out/amd64) --openssldir=$(realpath out/amd64) -g -O2 CC=clang
make clean -j8
make -j8
