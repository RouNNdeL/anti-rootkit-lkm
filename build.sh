#!/usr/bin/env bash
set -e

nproc=${1:-$(nproc)}

mkdir -p output/rootfs/home/bso

echo "Copying config files"
cp config/buildroot.config buildroot/.config
cp config/kernel.config kernel/.config

echo "Building the kernel modules"
cd module
make

echo "Copying modules to the rootfs overlay"
cp *.ko ../output/rootfs/home/bso/

echo "Building the ext4 rootfs with buildroot"
cd ../buildroot
make

echo "Building the kernel"
cd ../kernel
make -j $nproc

echo "Done!"
