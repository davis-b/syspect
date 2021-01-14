# syspect #

### What is _syspect_? ###


In as few words as possible, _syspect_ is a library that allows you to view and modify [syscalls](https://en.wikipedia.org/wiki/System_call) made by other programs.

In a little more detail, _syspect_ allows you to:

* Spawn or attach to a running program (hereafter known as the tracee).
* Pause the tracee when any syscall is started or finished, resuming the tracee at will.
* Modify any syscall's arguments before it is executed by the kernel.
* Modify any syscall's result before it is returned to the tracee.

### More Info ###

_syspect_ is a syscall inspection/modification library built upon [ptrace](https://en.wikipedia.org/wiki/Ptrace).  
_syspect_ is built in [zig](https://ziglang.org/), a C-like programming language.

#### What is ptrace? ####
_ptrace_ is a debugging interface provided by many \*nix kernels. While used to great effect by debuggers such as [gdb](https://www.gnu.org/software/gdb/), it is somewhat complex.

#### How does this relate to _syspect_? ####
To get _ptrace_ working correctly, especially when dealing with multiple tracees at once, requires knowledge of the underlying operating system that may not be necessary for the resulting program.  
This is where _syspect_ comes in. _syspect_ is easy to use and hard to misuse.  
If you are writing a program that can make good use of it, _syspect_ aims to make your life easier than _ptrace_ would.

- - -

### Which architectures / operating systems does _syspect_ support? ###

Currently, _syspect_ only supports x86_64 Linux.  
Support for other CPU architectures is a possibility for future updates.  
Support for other operating systems is possible if they implement _ptrace_.

### Are there any other requirements? ###

zig version 0.6.0 is required to use this library.  
_syspect_ does link against C in order to use ptrace. That requirement should not be a problem, though it is worth mentioning.

- - -

# Getting started with _syspect_ #

To begin learning the _syspect_ library, the best place to start would be the example programs. They are small and hopefully easy to understand.  
If you like to browse code to get a grasp of a library, the _src/syspect.zig_ file is where you will want to start. This file contains the _Inspector_ structure, which is where the majority of the public facing code is located.

## Code Flow Overview ##

### Init ###
A program using the _syspect_ library will begin by initializing an _Inspector_ struct. This is the structure we will be using to interact with the rest of the _syspect_ library.  
In the init call, _Inspector_ is to be given a slice of syscalls (referred to from now on as syscalls) that we want to pause the tracee (program we are inspecting) at and inspect or modify in our own code.  
As well as the slice of syscalls and the allocator, _Inspector_ may optionally be given up to two options. Those are "multithread" and "inverse". When "multithread" is true, _Inspector_ will automatically begin tracing the child threads and processes of the initially traced program. When "inverse" is true, the slice of syscalls we give the structure changes from a 'watch list' to an 'ignore list'.

### Attaching to a tracee ###
From there, we will either attach to a running process, or spawn a child process. Regardless of which option is chosen, the _Inspector_ will have its first tracee.  
The tracee will continue running as usual until it encounters a syscall that we are wanting to inspect, at which point its execution will be halted until we resume it.

### next_syscall ###
To access the syscall a program is halted at, we call the "next_syscall" method of _Inspector_.
"next_syscall" is a blocking function. Under the hood, it calls waitpid(2).  
This function will return when, in a traced program, a syscall that matches our provided filter either starts or finishes.  

When "next_syscall" returns a non-null value, it means the tracee returned by waitpid(2) is halted until we resume it.
"next_syscall" returns a tagged union. The tags are "pre_call" and "post_call", both contain an instance of a _Context_ structure.  
"next_syscall" can also return "null" when all tracees have exited.

**What does it mean when the "next_syscall" result indicates we are in a pre_call state?**  
The tracee has initiated a syscall. The syscall has not yet been executed by the kernel.  
Note that we cannot prevent a syscall from happening once it has been initiated. However, we can modify the registers that will be read by the kernel, thereby invalidating or otherwise altering the syscall. This means changing anything from arguments to the syscall number itself!  
We can, at this point, turn a write call into a read call.  

**How about when the result indicates we are in a post_call state?**  
At this point, the syscall has finished.  
When we resume the tracee, it will receive the result of the syscall.  
However, before resuming the tracee, we can view and even modify the syscall's return value (register rax on x86_64).  

### Resuming the tracee ###
Once we have finished inspecting a syscall, we must resume the halted tracee.
This is done with a simple _Inspector.resume_tracee()_ call.  
From here, we generally call "next_syscall" again and repeat the process as desired.

- - -

## Example Program ##
You can find more in-depth example programs in the _examples_ folder.  
This program prints the pathname of any open(2) or openat(2) calls ran by its tracee.  
_ls_ is the hard-coded executable we will be tracing in this example. For a more fleshed out version of this program, please look for "print_pathname.zig" in the examples folder.

The output should look something like:  
`zig run example.zig -lc`  
`pid = #####, 'openat' path = '.'`  
`pid = #####, 'openat' = #`

where '#' is a number.

- - -

``` zig
const std = @import("std");
const warn = std.debug.warn;

const syspect = @import("path_to_syspect_folder/src/index.zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const syscalls = &[_]std.os.SYS{
        .open,
        .openat,
    };

    var inspector = syspect.Inspector.init(allocator, syscalls, .{ .multithread = true });
    defer inspector.deinit();
    const args = [_][]const u8{ "ls", "." };
    // Spawns the process and associated arguments located in 'args', then immediately begins tracing the process.
    const tracee_pid = try inspector.spawn_process(allocator, args[0..]);

    while (try inspector.next_syscall()) |position_context| {
		// Here we are unwrapping a tagged union, which tells us if the syscall has been executed or not.
        switch (position_context) {
            // The syscall will be executed after we resume the tracee.
            // Now is our chance to inspect and even modify the arguments or tracee's memory.
            .pre_call => |context| {
                var buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
                // openat(2) and open(2) share all arguments/argument positions, except for openat(2)'s first argument.
                const pathname = switch (@intToEnum(std.os.SYS, context.registers.syscall)) {
                    .open => try readString(context.pid, context.registers.arg1, buffer[0..]),
                    .openat => try readString(context.pid, context.registers.arg2, buffer[0..]),
                    else => unreachable,
                };
                warn("pid = {}, '{}' path = '{}'\n", .{ context.pid, @tagName(@intToEnum(std.os.SYS, context.registers.syscall)), pathname });

                try inspector.resume_tracee(context.pid);
            },
            // The syscall has finished and the result will be returned to the tracee when resumed.
            // Here we can view the result as well as modify what the tracee will see as the return value.
            .post_call => |context| {
                warn("pid = {}, '{}' = {}\n\n", .{ context.pid, @tagName(@intToEnum(std.os.SYS, context.registers.syscall)), @intCast(isize, context.registers.result) });
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

/// Reads data as a string until we reach a null termination character.
/// Takes a pointer to a string. The pointer does not have to point to our memory space.
/// Can read data from other processes by utilizing "syspect.interprocess_rw"
fn readString(pid: std.os.pid_t, ptr: usize, buffer: []u8) ![]u8 {
    const vmreadv_result = try syspect.interprocess_rw.readv(pid, buffer[0..], ptr);

    for (buffer) |i, index| {
        if (i == 0) return buffer[0..index];
    }
    @panic("Filename end was not found!");
}
```
