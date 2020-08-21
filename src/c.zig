usingnamespace @cImport({
    @cInclude("sys/ptrace.h");

    // user_regs_struct
    @cInclude("sys/user.h");

    // process_vm_readv
    @cInclude("sys/uio.h");

    // struct sockaddr; socklen_t
    @cInclude("sys/socket.h");
});
