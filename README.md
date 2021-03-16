# Intro
A simple anti-rootkit kernel module developed as a project for a university course. WIP.

The project assumes a kernel is build from source.
Buildroot is used to generate a rootfs for a VM to test and develop the module.

# Development 
1. Clone this repo
2. Initialize and update the submodules with `git submoule init && git submodule update` (or pass the `--recurse-submodules` flag when cloning).
3. Copy the `config/kernel.config` to the `kernel/` directory.
4. Build the kernel with `make` (only needs to be done once). 
5. Build the module and create a rootfs with `./build.sh`.
6. Run the QEMU VM with `./run.sh`

# Open source licenses

- [ftrace hooking](https://github.com/ilammy/ftrace-hook) - GPLv2
