const builtin = @import("builtin");

pub usingnamespace @import("syspect.zig");

pub const ptrace = @import("ptrace.zig");
pub const c = @import("c.zig");

// Not required for Syspect.
// However, it is convenient to bundle them together.
// Projects that want to do system call inspection may
//  also want to read/write to that other process' memory.
pub const interprocess_rw = @import("helpers/interprocess_rw.zig");
