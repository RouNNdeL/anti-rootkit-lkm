bits 64
global _start

section .rodata
path:
	db "/root/.ash_history", 0

section .text
_start:
	; 24 bytes on the stack
	sub rsp, 0x18
	mov rdi, path
	mov rax, 90
	mov rsi, 0x1a4
	syscall
	mov rdi, rax
	mov rax, 60
	syscall
