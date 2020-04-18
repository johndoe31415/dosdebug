# doscheat
This is a collections of tools I am using to cheat and reverse engineer DOS
applications which run in DOSBox. In particular, it uses my
[pygdb](https://github.com/johndoe31415/pygdb) frontend to GDB to hook into
DOSBox, thereby allowing for breaks on read using hardware breakpoints
(something the DOSBox native debugger does not support).

## Running this
  * Compile DOSBox in heavy debugging mode
  * Ensure that in the config file `autolock=false` is set
  * Open dosbox through pygdb: `pygdb dosbox.json` (alternatively and without
    many of the functionality, directly run through gdb:
    `gdb -x gdbinit_dosbox.conf ./dosbox-0.74-3-dbg`

## Hardware breakpoint (on read)
  * Press Alt-Pause to enter DOSBox debugger; then memdump whole image using
    `memdumpbin 0:0 100000`
  * Find reference in `MEMDUMP.BIN` file you're looking for, note offset (e.g.,
    0x12345)
  * Convert to host address space using `addr 0:12345`, note down host address
    (e.g., 0x7fffffff9876)
  * Press Ctrl-C to enter GDB console, Ctrl-L to clear screen
  * gdb: `rwatch *0x0x7fffffff9876` and then `c` to continue
  * Wait for breakpoint to trigger
  * Find out guest instruction pointer: `printf "%04x:%04x\n", Segs.val[1],
    cpu_regs.ip.dword[0]` (or `gip`)

## Enabling DOSBox debugger from gdb
  * `call DEBUG_EnableDebugger()`

## Implemented gdb commands
The gdb is enhanced when run through pygdb in the following ways:
  * `gregs`: Print the DOS register set
  * `gip`: Print the DOS instruction pointer in segment:address notation
  * `ghexdump (addr) (len)`: Dump memory as hexdump starting from given address
    for a specific length.
  * `gbt`: Attempt to print a guest backtrace by doing stackframe unwinding.
    Super dodgy, doesn't work entirely yet.

## License
GNU GPL-3.
