This is a simple anti-rootkit Linux Kernel Module written for a _Operating Systems Securiy_ course.
It contains 7 (TODO: 8) different kernel integrity checks.
It is only compatible with the `x86_64` architecture, but some non architecture specific checks can be used on a different architecture.

<details open="open">
  <summary>Table of Contents</summary>

1. [About the project](#about)
2. [Installation](#installation)
3. [Available checks](#available-checks)
    1. [Pinned CR bits](#pinned-cr-bits)
    2. [MSR LSTAR](#msr-lstar)
    3. [Syscall Table](#syscall-table)
    4. [Interrupt Descriptor Table](#interrupt-descriptor-table)
4. [Development](#development)

</details>

# About

TODO

# Installation

## Kernel headers

To build the module you will need the header files for your kernel.
Depending on the distribution they might be in different packages.

### Arch Linux

`pacman -S linux-headers`

### Debian, Ubuntu or Linux Mint

`apt install linux-headers-$(uname -r)`

### Fedora, CentOS or RHEL

`yum install kernel-devel`

## Installing the module

1. Go to the `modules/anti_rootkit` directory
2. Build the module with `make`
3. Install the module with `insmod anti_rootkit.ko`

# Available checks
## Pinned CR bits

The first, and the most simple check is the `PINNED_BITS` check.
It checks up to 5 bits in 2 control registers `cr0` and `cr4`:
- `cr0` - bit is always checked
    - Write Protect (WP) - When cleared, the CPU can write to read-only pages, when running in ring 0. When set and a write is attempted the CPU will generate a page fault.
- `cr4` - bits are only checked when the CPU supports them
    - User-Mode Instruction Prevention (UMIP) - When set the `SGDT`, `SIDT`, `SLDT`, `SMSW` and `STR` instructions cannot be executed in user mode. Those instructions are mostly related to the different descriptor tables. The `SIDT` instruction is explained in more details in the [Interrupt Descriptor Table](#interrupt-descriptor-table) section.
    - Supervisor Mode Execution Protection (SMEP) - When set, an attempt to execute code from userspace in kernel mode generates a fault.
    - Supervisor Mode Access Prevention (SMAP) - Similar to SMEP, but generates a fault when any data access is attempted.

Those bits should always be set during normal operation, and in kernel 5.3 the common functions
`native_write_cr0` and `native_write_cr4` were changed to always set those bits,
and warn when an attempt was made to clear any of them.

Two related commits (`8dbec27a242cd3e2` and `873d50d58f67ef15`) implemented these checks for CR4 and CR0 registers respectively.

> x86/asm: Pin sensitive CR4 bits
>
> Several recent exploits have used direct calls to the native_write_cr4()
> function to disable SMEP and SMAP before then continuing their exploits
> using userspace memory access.
>
> Direct calls of this form can be mitigate by pinning bits of CR4 so that
> they cannot be changed through a common function. This is not intended to
> be a general ROP protection (which would require CFI to defend against
> properly), but rather a way to avoid trivial direct function calling (or
> CFI bypasses via a matching function prototype) as seen in:
>
> https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
>
> (https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-7308)

> x86/asm: Pin sensitive CR0 bits
>
> With sensitive CR4 bits pinned now, it's possible that the WP bit for
> CR0 might become a target as well.

The POC exploit was able to call the `native_write_cr4` function after bypassing KASLR
and calculating the offset to the function. Then it cleared the
SMEP and SMAP bits,
which in turn allowed the payload to be executed with ring 0 privileges.

It is obviously still possible to write to these registers in kernel mode, by implementing the function
without any checks.

```c
static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}
```

A malicious module might clear the WP bit to overwrite important kernel structures,
such as but not limited to:
- system call entries of the `syscall_table`
- `gate_desc` entries of the `itd_table`

or to hook kernel functions (later checks confirm the integrity of those structures and selected functions
to make sure have not been overwritten or hooked).

Usually the bit will be set back after the write is completed, but there's a chance that it won't be,
and those bits are an integral part of the kernel security, so we have to make sure they are set.


## MSR LSTAR

The next check is also simple, but one of the most important checks in the whole project.
On x86_64 the `syscall` instruction is used to enter kernel mode from user mode.
The Intel Software Developer Manual describes it's operation as such:

> Description SYSCALL invokes an OS system-call handler at privilege level 0.
> It does so by loading RIP from the IA32_LSTAR MSR (after saving the address of the instruction following SYSCALL into RCX).

So, the CPU will enter ring 0 (the kernel mode), and than jump to the address specified by the model-specific register `LSTAR`.
The kernel sets the value of the `MSR_LSTAR` in the `syscall_init` function to point to `entry_SYSCALL_64`.

```c
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```

A malicious module might want to overwrite the register's value to intercept all system calls.
If we are loaded into an unmodified kernel we can store the address of `entry_SYSCALL_64`
and detect any potential attempts to overwrite the address by periodically checking the value of the register.

If, however, we are loaded after a malicious module, and we suspect it has overwritten the register,
we can still detect, and potentially recover it's value by using kallsyms. The `sprintf_symbol` function allows us to
check the symbol name of the function pointed to by the `MSR_LSTAR`.
We could also check the alignment of the `entry_SYSCALL_64`, it should be paged aligned (the address ends in `0000`),
but I've noticed that we can do even better. When building kernel `5.11` with the supplied config it is aligned
to a 16 page boundary, meaning the address ends in `00000` (5 zeros, instead of 4).


## Syscall table

Having protected the syscall handler entry via the `syscall` instruction (at least in long mode,
we address the compatibility mode in the [Interrupt Descriptor Table](#interrupt-descriptor-table) section)
the next logical step is to protect the syscall table itself.

In older kernel versions (prior to 4.17) it was possible to locate the syscall table by searching
through the kernel address space and looking for references to the `sys_close` function (more precisely, it's address).
However, commit `2ca2a09d6215fd96` removed the export for `sys_close` and replaced it's usages with a `ksys_close` wrapper,
making this approach unviable.
The syscall table is also not available through kallsyms.

We have to get a bit clever to get access to the table. Let's follow what the CPU does to call a specific syscall handler.

We already know, when the `syscall` instruction gets executed, we jump to the `entry_SYSCALL_64`,
and the address of the next instruction is stored in the `rcx` register.
The procedure is actually written in assembly (in the `/arch/x86/entry/entry_64.S` file).

```asm
entry_SYSCALL_64:
  /* Prepare the stack */
  ...
  /* Construct struct pt_regs on the stack */
  ...
  push  rcx          /* pt_regs->ip (CPU stored it here on syscall) */
  push  rax          /* pt_regs->orig_ax */

  /* pushes and clears (using xor %r, %r) all registers except for rax, since it holds the syscall number */ 
  PUSH_AND_CLEAR_REGS rax=$-ENOSYS

  /* IRQs are off. */
  mov  rdi, rax            /* unsigned long nr */
  mov  rsi, rsp            /* struct pt_regs *regs */
  call  do_syscall_64      /* returns with IRQs disabled */
  /* now rax has the return value of the handler */
  ...
```

It  will first push the registers onto the stack (the `struct pt_regs` structure) and then call `do_syscall_64`
with the first argument `rdi` being the syscall number (also stored in `rax`),
and the second argument being the `struct pt_regs` structure holding the other registers (`mov rsi, rsp`;
remember that `struct pt_regs` is now on the stack).

The `do_syscall_64` function will check if the syscall number is valid and then call the appropriate syscall,
like this:

```c
regs->ax = sys_call_table[nr](regs);
```

There it is, a reference to the `sys_call_table` (btw, note the inconsistency _syscall_ and *sys_call*).
If the CPU knows where to lookup the address to jump to, we can too!

Since `entry_SYSCALL_64` is written in assembly, and it is not changed to often,
we can calculate a static offset to the `call do_syscall_64` instruction like this:

```c
// First byte of call is the opcode, following 4 bytes are the signed offset
offset = *((int *)(entry_syscall + ENTRY_DO_CALL_OFFSET + 1));
```

The `do_syscall_64` function will be located at:

```c
// The call offset should include the 5 instruction bytes
do_syscall = entry_syscall + offset + ENTRY_DO_CALL_OFFSET + 5;
```

The next part is a bit tricky, since the `do_syscall_64` is written in C, so we have to apply
some heuristics, as we cannot be certain what the compiler will generate.
This is how the jump is compiled with my `gcc`:

```asm
mov rax, qword [rax*8 - 0x7e3ffde0]
call sym.__x86_indirect_thunk_rax ; retpoline - basically jmp rax
```

We can now attempt to locate this part by pattern matching,
looking for the `mov` instruction - specifically `MOV r64,r/m64`.
Additionally the value of the ModR/M Byte has to be equal to `04`, meaning `mov rax, ?`,
the SIB Byte follows the ModR/M Byte to describe the source operand.
Moreover SIB Byte has to be equal to `c5` since we are multiplying `rax` by 8
(`sizeof(void *)`; `rax` is the syscall number)
and combine it with the 32 bit displacement.

The format of the `mov` instruction is as follows.

```
488b04c5????????

48 - REX.W
8b - MOV r64,r/m64
04 - ModR/M Byte - destination operand is RAX, SIB Byte follows
c5 - SIB Byte - source operand is rax*8 + disp32
???????? - disp32
```

Armed with this knowledge, we can now attempt to find this instruction in the first few
hundred bytes of the `do_syscall_64` function.
Then it's as simple as extracting the offset (`disp32`) and we can calculate the address
of the syscall table remembering to sign extend the displacement.

This is by no means a perfect approach, since the compiler might generate
a completely different code. However, it should be pretty easy to add
more patterns by analyzing the `do_syscall_64` assembly.
More advanced techniques are possible, such as dynamically instrumenting the syscall handler
and analyzing it's memory access, but that was beyond the scope of this project.

When we finally get the address of the syscall table, we can create a copy of it,
and check for any anomalies. Since we have a full copy, we can not only detect
any attempts to tamper with the table, but also recover it, if we notice anything out of place.

## Interrupt Descriptor Table

Already mentioned a couple of times, the Interrupt Descriptor Table, or IDT for short is a data structure
used by x86. It associates a list of interrupts and exceptions with their respective handlers.
Many important interrupt handlers are referenced in the IDT, in particular the `0x80` 32 bit syscall handler.

The kernel initializes the IDT very early on in `trap_init` just before calling `cpu_init`.
The `struct desc_ptr idt_descr` structure contains the size and address of the IDT,
and is persisted to the 80 bit `idtr` register using the `lidt` instruction.

Definition of the 80 bit `desc_ptr` structure:
```c
struct desc_ptr {
    unsigned short size;
    unsigned long address;
} __attribute__((packed));
```

The operation of the `lidt` instruction in 64 bit mode:

```
IDTR(Limit) ← SRC[0:15];
IDTR(Base) ← SRC[16:79];
```

Getting the address of the IDT is much much simpler then accessing the syscall table.
We can either directly use the `sidt` instruction to load the contents of `idtr` into a `struct desc_ptr`,
or even simpler, just use the function included from `asm/desc.h` - `void store_idt(struct desc_ptr *dtr)`.

Once we have to address of the IDT, we can create a copy just like we did for the syscall table
and monitor it for any changes.

# Development

1. Clone this repo.
2. Initialize and update the submodules with `git submoule init && git submodule update` (or pass the `--recurse-submodules` flag when cloning).
3. Copy the `config/kernel.config` to the `kernel/` directory.
4. Build the kernel with `make` (only needs to be done once).
5. Build the modules and create a rootfs with `./build.sh`.
6. Run the QEMU VM with `./run.sh`.

## Open source licenses

- [ftrace hooking](https://github.com/ilammy/ftrace-hook) - GPLv2
