# dosdebug
This is a collections of tools I am using reverse engineer DOS applications
which run in DOSBox. My main purpose is to cheat at old DOS games and there's a
collection of found offsets in the cheats/ subdirectory. The tools use my
[pygdb](https://github.com/johndoe31415/pygdb) frontend to GDB to hook into
DOSBox, thereby allowing for breaks on read using hardware breakpoints
(something the DOSBox native debugger does not support). Additionally, they
support sophisticated manipulation of DOSBox full trace logs and evaluating
system calls. There's an engine that can transform multiple instructions into
single pseudo-ops, e.g., a 32-bit multiplication on 16-bit mode will be
typically 20 opcodes which can be automatically simplified.

## Tracing
When you've collected a DOSBox trace, you first have to convert it from TXT
format to JSON. This is simple enough:

```
$ ./trace_to_json.py LOGCPU.TXT my_log.json
```

Then, you can print system calls in there in an strace-fashion. Note that only
those syscalls are implemented that I'm interested in, but feel free to add
more:

```
$ ./dos_strace.py my_log.json
3: [3d] OPEN mode = read, filename = 01e3:0127 -> handle = 5
10: [3d] OPEN mode = read, filename = 01e3:0127 -> handle = 6
18: [3e] CLOSE handle = 6 -> success = True
24: [3e] CLOSE handle = 6 -> error = invalid handle
30: [3e] CLOSE handle = 5 -> success = True
35: [4c] EXIT returncode = 0
```

You can also filter the trace files, e.g., if you have an extremely large trace
file, identified using syscall analysis the portion you're interested in and
want just that:

```
$ ./trace_filter.py -i all --start 5 --stop 8 my_log.json short.json
```

This transfers all tracepoints from line 5 to 8 (both inclusive) into the file
`short.json`. However, you can also just extract syscall instructions, e.g.:

```
$ ./trace_filter.py -i syscall my_log.json syscalls_only.json
```

You can also print the log and there's a wide variety of options available to print them nicely:

```
$ ./dos_printtrace.py my_log.json
     1   01e3:0100: mov  dx,0127                                                       0 ax      0 bx     ff cx    1e3 dx    100 si   fffe di    91c bp   fffe sp
     2   01e3:0103: mov  ax,3d00                                                                                   127 dx
     3   01e3:0106: int  21                                                         3d00 ax
     4   f000:14c0: sti                                                                                                                                   fff8 sp
     5   f000:14c1: callback 0026  (dos int 21)
     6   f000:14c5: iret                                                               5 ax
     7   01e3:0108: push ax                                                                                                                               fffe sp
     8   01e3:0109: mov  dx,0127                                                                                                                          fffc sp
```

Additionally, you can define labels for addresses (both jump labels and/or
memory labels) as well as notes at specific tracepoints. Look at
`labels_example.json` for an example and use the `--labels` option of
`dos_printtrace.py`.

Finally, you can run code transformations and pseudocode substitutions on your
code. Some common ones are shown in `GenericSubstitutions.py`. Essentially, it
allows really easy regex-style matching on instructions and allows replacing
them with something different.

## Usage
All tools have a respective help page:

```
usage: trace_to_json.py [-h] [--start insn_no] [--stop insn_no] [-v]
                        infile outfile

Convert DosBox full trace to JSON format.

positional arguments:
  infile           Input trace file (typically called LOGCPU.TXT)
  outfile          Output JSON file

optional arguments:
  -h, --help       show this help message and exit
  --start insn_no  First line to include in tracefile. Defaults to 1.
  --stop insn_no   Last line to include in tracefile. Defaults to end of file.
  -v, --verbose    Increases verbosity. Can be specified multiple times to
                   increase.
```

```
usage: trace_filter.py [-h] -i {all,syscall} [--start insn_no]
                       [--stop insn_no] [-v]
                       infile outfile

Filter a DosBox full trace file to JSON format.

positional arguments:
  infile                Input trace file in JSON format
  outfile               Output trace file, filtered, in JSON format

optional arguments:
  -h, --help            show this help message and exit
  -i {all,syscall}, --include {all,syscall}
                        Include which portions of the original trace file. Can
                        be any of all, syscall and can be specified multiple
                        times. Must be given at least once.
  --start insn_no       First instruction to include in tracefile. Defaults to
                        1.
  --stop insn_no        Last instruction to include in tracefile. Defaults to
                        last instruction.
  -v, --verbose         Increases verbosity. Can be specified multiple times
                        to increase.
```


```
usage: dos_printtrace.py [-h] [-l file] [-c file] [-s file]
                         [-a {actual,linear,normalized}] [--show-hidden]
                         [--full-regs] [-v]
                         infile

Print a DOSBox trace log in JSON format.

positional arguments:
  infile                Input trace file in JSON format

optional arguments:
  -h, --help            show this help message and exit
  -l file, --labels file
                        Read label definition from this file.
  -c file, --config file
                        Substitutions are passed configuration, consisting of
                        a dictionary. This is parsed from a JSON document. Can
                        also be specified multiple times, later options will
                        override previous settings.
  -s file, --substitute file
                        Run specific substitutions laid out in a Python file;
                        can be specified multiple times to run more than one
                        module. These can be used to pretty-print code or
                        combine multiple instructions into pseudo-ops to
                        improve readablility (e.g., 32 bit addition or
                        multiplication in 16 bit mode).
  -a {actual,linear,normalized}, --address {actual,linear,normalized}
                        Display addresses of instructions in different modes.
                        Can be any of actual, linear, normalized, defaults to
                        actual.
  --show-hidden         Show instructions that would be hidden (e.g., because
                        they've been replaced by pseudo-ops)
  --full-regs           Show full register set for every instruction instead
                        of just the delta.
  -v, --verbose         Increases verbosity. Can be specified multiple times
                        to increase.
```

```
usage: dos_strace.py [-h] [-v] infile

Perform a DosBox system call trace on a trace log in JSON format.

positional arguments:
  infile         Input trace file in JSON format

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Increases verbosity. Can be specified multiple times to
                 increase.
```

## Running the debugger
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
