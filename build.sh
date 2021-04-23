#!/usr/bin/env bash
set -e

nproc=${1:-$(nproc)}
kernel="$PWD/kernel"

mkdir -p output/rootfs/home/bso

echo "Copying config files"
cp config/buildroot.config buildroot/.config
cp config/kernel.config kernel/.config

echo "Building the kernel modules"
cd module/anti_rootkit
KERNEL="$kernel" make
cd ..
cd samples
KERNEL="$kernel" make
cd ../..

echo "Copying modules to the rootfs overlay"
cp module/*/*.ko output/rootfs/home/bso/

echo "Building the ext4 rootfs with buildroot"
cd buildroot
make

echo "Done!"
