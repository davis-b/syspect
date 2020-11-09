/// File contains functions for reading and writing 'os.sockaddr' to/from
///  the memory of another process.
const std = @import("std");
const os = std.os;
const mem = std.mem;
const warn = std.debug.warn;

const syspect = @import("syspect");
const c = syspect.c;
const process_vm = syspect.interprocess_rw;
const ptrace = syspect.ptrace.ptrace;

/// Reads memory from another process using process_vm_readv
/// Returns os.sockaddr found at that memory location
pub fn readSockaddr_PVReadv(pid: os.pid_t, ptr: usize) !os.sockaddr {
    var buffer = [_]u8{0} ** @sizeOf(os.sockaddr);
    const vmreadv_result = try process_vm.readv(pid, buffer[0..], ptr);
    const sockaddr = mem.bytesToValue(os.sockaddr, buffer[0..]);
    return sockaddr;
}

pub fn writeSockaddr_PVWritev(pid: os.pid_t, ptr: usize, sockaddr: os.sockaddr) !usize {
    var buffer = mem.toBytes(sockaddr);
    const written = try process_vm.writev(pid, buffer[0..], ptr);
    return written;
}

/// Reads memory from another process using Ptrace's PEEKTEXT
/// Returns os.sockaddr found at that memory location
pub fn readSockaddr_Ptrace(pid: os.pid_t, ptr: usize) !os.sockaddr {
    // holds results of two PEEKTEXT calls. Both of these calls returns 64 bits of data
    var buffer = [_]u8{0} ** 16;

    var result_bytes = [_]u8{0} ** 8;
    var result: c_long = undefined;

    for ([_]u1{0} ** 2) |_, iteration| {
        const extra_bytes = 8 * iteration;
        result = try ptrace(c.PTRACE_PEEKTEXT, pid, ptr + extra_bytes, 0);
        result_bytes = mem.toBytes(result);
        for (result_bytes) |i, n| buffer[n + extra_bytes] = i;
    }

    const sockaddr = mem.bytesToValue(os.sockaddr, buffer[0..]);
    return sockaddr;
}

pub fn writeSockaddr_Ptrace(pid: os.pid_t, ptr: usize, addr: os.sockaddr) !void {
    const addr_bytes = mem.toBytes(addr);
    const data = mem.bytesAsSlice(c_long, addr_bytes[0..]);
    for ([_]u1{0} ** 2) |_, iteration| {
        _ = try ptrace(c.PTRACE_POKETEXT, pid, ptr + iteration * 8, data[iteration]);
    }
}
