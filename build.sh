#!/usr/bin/env bash
set -e

nproc=${1:-$(nproc)}

mkdir -p output/rootfs/home/bso

echo "Copying config files"
cp config/buildroot.config buildroot/.config
cp config/kernel.config kernel/.config

echo "Building the kernel modules"
cd module/anti_rootkit
make

echo "Copying modules to the rootfs overlay"
cp *.ko ../../output/rootfs/home/bso/

cd ../..
echo "Building the ext4 rootfs with buildroot"
cd buildroot
make

echo "Done!"
