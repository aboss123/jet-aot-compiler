#pragma once

//============================================================================
// Syscall Constants for macOS and Linux
// Based on mac-syscalls.txt and standard Linux syscall numbers
//============================================================================

#include <cstdint>

namespace SyscallConstants {

//============================================================================
// macOS Syscall Numbers (Darwin)
//============================================================================

// Basic I/O syscalls
static constexpr uint32_t MACOS_SYS_EXIT = 1;
static constexpr uint32_t MACOS_SYS_FORK = 2;
static constexpr uint32_t MACOS_SYS_READ = 3;
static constexpr uint32_t MACOS_SYS_WRITE = 4;
static constexpr uint32_t MACOS_SYS_OPEN = 5;
static constexpr uint32_t MACOS_SYS_CLOSE = 6;
static constexpr uint32_t MACOS_SYS_WAIT4 = 7;

// File operations
static constexpr uint32_t MACOS_SYS_LINK = 9;
static constexpr uint32_t MACOS_SYS_UNLINK = 10;
static constexpr uint32_t MACOS_SYS_CHDIR = 12;
static constexpr uint32_t MACOS_SYS_FCHDIR = 13;
static constexpr uint32_t MACOS_SYS_MKNOD = 14;
static constexpr uint32_t MACOS_SYS_CHMOD = 15;
static constexpr uint32_t MACOS_SYS_CHOWN = 16;
static constexpr uint32_t MACOS_SYS_GETFSSTAT = 18;

// Process management
static constexpr uint32_t MACOS_SYS_GETPID = 20;
static constexpr uint32_t MACOS_SYS_SETUID = 23;
static constexpr uint32_t MACOS_SYS_GETUID = 24;
static constexpr uint32_t MACOS_SYS_GETEUID = 25;
static constexpr uint32_t MACOS_SYS_GETPPID = 39;
static constexpr uint32_t MACOS_SYS_GETGID = 47;
static constexpr uint32_t MACOS_SYS_GETEGID = 43;

// Memory management
static constexpr uint32_t MACOS_SYS_MUNMAP = 73;
static constexpr uint32_t MACOS_SYS_MPROTECT = 74;
static constexpr uint32_t MACOS_SYS_MADVISE = 75;
static constexpr uint32_t MACOS_SYS_MINCORE = 78;
static constexpr uint32_t MACOS_SYS_MSYNC = 65;

// File descriptor operations
static constexpr uint32_t MACOS_SYS_DUP = 41;
static constexpr uint32_t MACOS_SYS_PIPE = 42;
static constexpr uint32_t MACOS_SYS_DUP2 = 90;
static constexpr uint32_t MACOS_SYS_GETDTABLESIZE = 89;

// Signal handling
static constexpr uint32_t MACOS_SYS_SIGACTION = 46;
static constexpr uint32_t MACOS_SYS_SIGPROCMASK = 48;
static constexpr uint32_t MACOS_SYS_SIGPENDING = 52;
static constexpr uint32_t MACOS_SYS_SIGALTSTACK = 53;
static constexpr uint32_t MACOS_SYS_KILL = 37;
static constexpr uint32_t MACOS_SYS_SIGSUSPEND = 111;

// I/O control and device operations
static constexpr uint32_t MACOS_SYS_IOCTL = 54;
static constexpr uint32_t MACOS_SYS_FCNTL = 92;
static constexpr uint32_t MACOS_SYS_SELECT = 93;
static constexpr uint32_t MACOS_SYS_FSYNC = 95;

// Time operations
static constexpr uint32_t MACOS_SYS_GETTIMEOFDAY = 116;
static constexpr uint32_t MACOS_SYS_SETTIMEOFDAY = 122;
static constexpr uint32_t MACOS_SYS_GETRUSAGE = 117;
static constexpr uint32_t MACOS_SYS_SETITIMER = 83;
static constexpr uint32_t MACOS_SYS_GETITIMER = 86;

// Process priority and scheduling
static constexpr uint32_t MACOS_SYS_SETPRIORITY = 96;
static constexpr uint32_t MACOS_SYS_GETPRIORITY = 100;
static constexpr uint32_t MACOS_SYS_GETPGRP = 81;
static constexpr uint32_t MACOS_SYS_SETPGID = 82;

// Group management
static constexpr uint32_t MACOS_SYS_GETGROUPS = 79;
static constexpr uint32_t MACOS_SYS_SETGROUPS = 80;

// Network operations
static constexpr uint32_t MACOS_SYS_SOCKET = 97;
static constexpr uint32_t MACOS_SYS_CONNECT = 98;
static constexpr uint32_t MACOS_SYS_BIND = 104;
static constexpr uint32_t MACOS_SYS_LISTEN = 106;
static constexpr uint32_t MACOS_SYS_ACCEPT = 30;
static constexpr uint32_t MACOS_SYS_SENDTO = 133;
static constexpr uint32_t MACOS_SYS_RECVFROM = 29;
static constexpr uint32_t MACOS_SYS_SENDMSG = 28;
static constexpr uint32_t MACOS_SYS_RECVMSG = 27;
static constexpr uint32_t MACOS_SYS_SHUTDOWN = 134;
static constexpr uint32_t MACOS_SYS_SOCKETPAIR = 135;
static constexpr uint32_t MACOS_SYS_SETSOCKOPT = 105;
static constexpr uint32_t MACOS_SYS_GETSOCKOPT = 118;
static constexpr uint32_t MACOS_SYS_GETPEERNAME = 31;
static constexpr uint32_t MACOS_SYS_GETSOCKNAME = 32;

// Scattered I/O
static constexpr uint32_t MACOS_SYS_READV = 120;
static constexpr uint32_t MACOS_SYS_WRITEV = 121;

// File system operations
static constexpr uint32_t MACOS_SYS_MKDIR = 136;
static constexpr uint32_t MACOS_SYS_RMDIR = 137;
static constexpr uint32_t MACOS_SYS_RENAME = 128;
static constexpr uint32_t MACOS_SYS_SYMLINK = 57;
static constexpr uint32_t MACOS_SYS_READLINK = 58;
static constexpr uint32_t MACOS_SYS_MKFIFO = 132;
static constexpr uint32_t MACOS_SYS_FLOCK = 131;

// Access control
static constexpr uint32_t MACOS_SYS_ACCESS = 33;
static constexpr uint32_t MACOS_SYS_CHFLAGS = 34;
static constexpr uint32_t MACOS_SYS_FCHFLAGS = 35;
static constexpr uint32_t MACOS_SYS_FCHOWN = 123;
static constexpr uint32_t MACOS_SYS_FCHMOD = 124;
static constexpr uint32_t MACOS_SYS_SETREUID = 126;
static constexpr uint32_t MACOS_SYS_SETREGID = 127;

// System control
static constexpr uint32_t MACOS_SYS_REBOOT = 55;
static constexpr uint32_t MACOS_SYS_REVOKE = 56;
static constexpr uint32_t MACOS_SYS_SYNC = 36;
static constexpr uint32_t MACOS_SYS_UMASK = 60;
static constexpr uint32_t MACOS_SYS_CHROOT = 61;
static constexpr uint32_t MACOS_SYS_ACCT = 51;
static constexpr uint32_t MACOS_SYS_SWAPON = 85;

// Process execution
static constexpr uint32_t MACOS_SYS_EXECVE = 59;
static constexpr uint32_t MACOS_SYS_VFORK = 66;

// Login and session management
static constexpr uint32_t MACOS_SYS_GETLOGIN = 49;
static constexpr uint32_t MACOS_SYS_SETLOGIN = 50;

// Debugging and tracing
static constexpr uint32_t MACOS_SYS_PTRACE = 26;

//============================================================================
// Linux Syscall Numbers (x86_64)
//============================================================================

// Basic I/O syscalls
static constexpr uint32_t LINUX_SYS_READ = 0;
static constexpr uint32_t LINUX_SYS_WRITE = 1;
static constexpr uint32_t LINUX_SYS_OPEN = 2;
static constexpr uint32_t LINUX_SYS_CLOSE = 3;
static constexpr uint32_t LINUX_SYS_STAT = 4;
static constexpr uint32_t LINUX_SYS_FSTAT = 5;
static constexpr uint32_t LINUX_SYS_LSTAT = 6;
static constexpr uint32_t LINUX_SYS_POLL = 7;
static constexpr uint32_t LINUX_SYS_LSEEK = 8;
static constexpr uint32_t LINUX_SYS_MMAP = 9;
static constexpr uint32_t LINUX_SYS_MPROTECT = 10;
static constexpr uint32_t LINUX_SYS_MUNMAP = 11;
static constexpr uint32_t LINUX_SYS_BRK = 12;
static constexpr uint32_t LINUX_SYS_RT_SIGACTION = 13;
static constexpr uint32_t LINUX_SYS_RT_SIGPROCMASK = 14;
static constexpr uint32_t LINUX_SYS_RT_SIGRETURN = 15;
static constexpr uint32_t LINUX_SYS_IOCTL = 16;
static constexpr uint32_t LINUX_SYS_PREAD64 = 17;
static constexpr uint32_t LINUX_SYS_PWRITE64 = 18;
static constexpr uint32_t LINUX_SYS_READV = 19;
static constexpr uint32_t LINUX_SYS_WRITEV = 20;
static constexpr uint32_t LINUX_SYS_ACCESS = 21;
static constexpr uint32_t LINUX_SYS_PIPE = 22;
static constexpr uint32_t LINUX_SYS_SELECT = 23;
static constexpr uint32_t LINUX_SYS_SCHED_YIELD = 24;
static constexpr uint32_t LINUX_SYS_MREMAP = 25;
static constexpr uint32_t LINUX_SYS_MSYNC = 26;
static constexpr uint32_t LINUX_SYS_MINCORE = 27;
static constexpr uint32_t LINUX_SYS_MADVISE = 28;
static constexpr uint32_t LINUX_SYS_SHMGET = 29;
static constexpr uint32_t LINUX_SYS_SHMAT = 30;
static constexpr uint32_t LINUX_SYS_SHMDT = 31;
static constexpr uint32_t LINUX_SYS_SOCKET = 41;
static constexpr uint32_t LINUX_SYS_CONNECT = 42;
static constexpr uint32_t LINUX_SYS_ACCEPT = 43;
static constexpr uint32_t LINUX_SYS_SENDTO = 44;
static constexpr uint32_t LINUX_SYS_RECVFROM = 45;
static constexpr uint32_t LINUX_SYS_SENDMSG = 46;
static constexpr uint32_t LINUX_SYS_RECVMSG = 47;
static constexpr uint32_t LINUX_SYS_SHUTDOWN = 48;
static constexpr uint32_t LINUX_SYS_BIND = 49;
static constexpr uint32_t LINUX_SYS_LISTEN = 50;
static constexpr uint32_t LINUX_SYS_GETSOCKNAME = 51;
static constexpr uint32_t LINUX_SYS_GETPEERNAME = 52;
static constexpr uint32_t LINUX_SYS_SOCKETPAIR = 53;
static constexpr uint32_t LINUX_SYS_SETSOCKOPT = 54;
static constexpr uint32_t LINUX_SYS_GETSOCKOPT = 55;
static constexpr uint32_t LINUX_SYS_CLONE = 56;
static constexpr uint32_t LINUX_SYS_FORK = 57;
static constexpr uint32_t LINUX_SYS_VFORK = 58;
static constexpr uint32_t LINUX_SYS_EXECVE = 59;
static constexpr uint32_t LINUX_SYS_EXIT = 60;
static constexpr uint32_t LINUX_SYS_WAIT4 = 61;
static constexpr uint32_t LINUX_SYS_KILL = 62;
static constexpr uint32_t LINUX_SYS_UNAME = 63;
static constexpr uint32_t LINUX_SYS_SEMGET = 64;
static constexpr uint32_t LINUX_SYS_SEMOP = 65;
static constexpr uint32_t LINUX_SYS_SEMCTL = 66;
static constexpr uint32_t LINUX_SYS_MSGGET = 68;
static constexpr uint32_t LINUX_SYS_MSGSND = 69;
static constexpr uint32_t LINUX_SYS_MSGRCV = 70;
static constexpr uint32_t LINUX_SYS_MSGCTL = 71;
static constexpr uint32_t LINUX_SYS_FCNTL = 72;
static constexpr uint32_t LINUX_SYS_FLOCK = 73;
static constexpr uint32_t LINUX_SYS_FSYNC = 74;
static constexpr uint32_t LINUX_SYS_FDATASYNC = 75;
static constexpr uint32_t LINUX_SYS_TRUNCATE = 76;
static constexpr uint32_t LINUX_SYS_FTRUNCATE = 77;
static constexpr uint32_t LINUX_SYS_GETDENTS = 78;
static constexpr uint32_t LINUX_SYS_GETCWD = 79;
static constexpr uint32_t LINUX_SYS_CHDIR = 80;
static constexpr uint32_t LINUX_SYS_FCHDIR = 81;
static constexpr uint32_t LINUX_SYS_RENAME = 82;
static constexpr uint32_t LINUX_SYS_MKDIR = 83;
static constexpr uint32_t LINUX_SYS_RMDIR = 84;
static constexpr uint32_t LINUX_SYS_CREAT = 85;
static constexpr uint32_t LINUX_SYS_LINK = 86;
static constexpr uint32_t LINUX_SYS_UNLINK = 87;
static constexpr uint32_t LINUX_SYS_SYMLINK = 88;
static constexpr uint32_t LINUX_SYS_READLINK = 89;
static constexpr uint32_t LINUX_SYS_CHMOD = 90;
static constexpr uint32_t LINUX_SYS_FCHMOD = 91;
static constexpr uint32_t LINUX_SYS_CHOWN = 92;
static constexpr uint32_t LINUX_SYS_FCHOWN = 93;
static constexpr uint32_t LINUX_SYS_LCHOWN = 94;
static constexpr uint32_t LINUX_SYS_UMASK = 95;
static constexpr uint32_t LINUX_SYS_GETTIMEOFDAY = 96;
static constexpr uint32_t LINUX_SYS_GETRLIMIT = 97;
static constexpr uint32_t LINUX_SYS_GETRUSAGE = 98;
static constexpr uint32_t LINUX_SYS_SYSINFO = 99;
static constexpr uint32_t LINUX_SYS_TIMES = 100;
static constexpr uint32_t LINUX_SYS_PTRACE = 101;
static constexpr uint32_t LINUX_SYS_GETUID = 102;
static constexpr uint32_t LINUX_SYS_SYSLOG = 103;
static constexpr uint32_t LINUX_SYS_GETGID = 104;
static constexpr uint32_t LINUX_SYS_SETUID = 105;
static constexpr uint32_t LINUX_SYS_SETGID = 106;
static constexpr uint32_t LINUX_SYS_GETEUID = 107;
static constexpr uint32_t LINUX_SYS_GETEGID = 108;
static constexpr uint32_t LINUX_SYS_SETPGID = 109;
static constexpr uint32_t LINUX_SYS_GETPPID = 110;
static constexpr uint32_t LINUX_SYS_GETPGRP = 111;
static constexpr uint32_t LINUX_SYS_SETSID = 112;
static constexpr uint32_t LINUX_SYS_SETREUID = 113;
static constexpr uint32_t LINUX_SYS_SETREGID = 114;
static constexpr uint32_t LINUX_SYS_GETGROUPS = 115;
static constexpr uint32_t LINUX_SYS_SETGROUPS = 116;
static constexpr uint32_t LINUX_SYS_SETRESUID = 117;
static constexpr uint32_t LINUX_SYS_GETRESUID = 118;
static constexpr uint32_t LINUX_SYS_SETRESGID = 119;
static constexpr uint32_t LINUX_SYS_GETRESGID = 120;
static constexpr uint32_t LINUX_SYS_GETPID = 39;
static constexpr uint32_t LINUX_SYS_DUP = 32;
static constexpr uint32_t LINUX_SYS_DUP2 = 33;
static constexpr uint32_t LINUX_SYS_PAUSE = 34;
static constexpr uint32_t LINUX_SYS_NANOSLEEP = 35;
static constexpr uint32_t LINUX_SYS_GETITIMER = 36;
static constexpr uint32_t LINUX_SYS_ALARM = 37;
static constexpr uint32_t LINUX_SYS_SETITIMER = 38;

//============================================================================
// Platform-specific syscall number mapping
//============================================================================

// macOS syscall offset (Darwin)
static constexpr uint64_t MACOS_SYSCALL_OFFSET = 0x2000000ULL;

// Get platform-specific syscall number
inline uint64_t get_platform_syscall_number(uint32_t syscall_number, bool is_macos) {
    if (is_macos) {
        return MACOS_SYSCALL_OFFSET | static_cast<uint64_t>(syscall_number);
    } else {
        return static_cast<uint64_t>(syscall_number);
    }
}

// Common syscall mappings
struct SyscallMapping {
    uint32_t macos_number;
    uint32_t linux_number;
    const char* name;
};

// Essential syscalls that should be implemented
static constexpr SyscallMapping ESSENTIAL_SYSCALLS[] = {
    {MACOS_SYS_EXIT, LINUX_SYS_EXIT, "exit"},
    {MACOS_SYS_READ, LINUX_SYS_READ, "read"},
    {MACOS_SYS_WRITE, LINUX_SYS_WRITE, "write"},
    {MACOS_SYS_OPEN, LINUX_SYS_OPEN, "open"},
    {MACOS_SYS_CLOSE, LINUX_SYS_CLOSE, "close"},
    {MACOS_SYS_FORK, LINUX_SYS_FORK, "fork"},
    {MACOS_SYS_WAIT4, LINUX_SYS_WAIT4, "wait4"},
    {MACOS_SYS_GETPID, LINUX_SYS_GETPID, "getpid"},
    {MACOS_SYS_GETUID, LINUX_SYS_GETUID, "getuid"},
    {MACOS_SYS_GETGID, LINUX_SYS_GETGID, "getgid"},
    {MACOS_SYS_CHDIR, LINUX_SYS_CHDIR, "chdir"},
    {MACOS_SYS_CHMOD, LINUX_SYS_CHMOD, "chmod"},
    {MACOS_SYS_CHOWN, LINUX_SYS_CHOWN, "chown"},
    {MACOS_SYS_MKDIR, LINUX_SYS_MKDIR, "mkdir"},
    {MACOS_SYS_RMDIR, LINUX_SYS_RMDIR, "rmdir"},
    {MACOS_SYS_UNLINK, LINUX_SYS_UNLINK, "unlink"},
    {MACOS_SYS_RENAME, LINUX_SYS_RENAME, "rename"},
    {MACOS_SYS_SYMLINK, LINUX_SYS_SYMLINK, "symlink"},
    {MACOS_SYS_READLINK, LINUX_SYS_READLINK, "readlink"},
    {MACOS_SYS_ACCESS, LINUX_SYS_ACCESS, "access"},
    {MACOS_SYS_GETTIMEOFDAY, LINUX_SYS_GETTIMEOFDAY, "gettimeofday"},
    {MACOS_SYS_GETRUSAGE, LINUX_SYS_GETRUSAGE, "getrusage"},
    {MACOS_SYS_SOCKET, LINUX_SYS_SOCKET, "socket"},
    {MACOS_SYS_CONNECT, LINUX_SYS_CONNECT, "connect"},
    {MACOS_SYS_BIND, LINUX_SYS_BIND, "bind"},
    {MACOS_SYS_LISTEN, LINUX_SYS_LISTEN, "listen"},
    {MACOS_SYS_ACCEPT, LINUX_SYS_ACCEPT, "accept"},
    {MACOS_SYS_SENDTO, LINUX_SYS_SENDTO, "sendto"},
    {MACOS_SYS_RECVFROM, LINUX_SYS_RECVFROM, "recvfrom"},
    {MACOS_SYS_SENDMSG, LINUX_SYS_SENDMSG, "sendmsg"},
    {MACOS_SYS_RECVMSG, LINUX_SYS_RECVMSG, "recvmsg"},
    {MACOS_SYS_SHUTDOWN, LINUX_SYS_SHUTDOWN, "shutdown"},
    {MACOS_SYS_SOCKETPAIR, LINUX_SYS_SOCKETPAIR, "socketpair"},
    {MACOS_SYS_SETSOCKOPT, LINUX_SYS_SETSOCKOPT, "setsockopt"},
    {MACOS_SYS_GETSOCKOPT, LINUX_SYS_GETSOCKOPT, "getsockopt"},
    {MACOS_SYS_GETPEERNAME, LINUX_SYS_GETPEERNAME, "getpeername"},
    {MACOS_SYS_GETSOCKNAME, LINUX_SYS_GETSOCKNAME, "getsockname"},
    {MACOS_SYS_READV, LINUX_SYS_READV, "readv"},
    {MACOS_SYS_WRITEV, LINUX_SYS_WRITEV, "writev"},
    {MACOS_SYS_IOCTL, LINUX_SYS_IOCTL, "ioctl"},
    {MACOS_SYS_FCNTL, LINUX_SYS_FCNTL, "fcntl"},
    {MACOS_SYS_SELECT, LINUX_SYS_SELECT, "select"},
    {MACOS_SYS_FSYNC, LINUX_SYS_FSYNC, "fsync"},
    {MACOS_SYS_DUP, LINUX_SYS_DUP, "dup"},
    {MACOS_SYS_DUP2, LINUX_SYS_DUP2, "dup2"},
    {MACOS_SYS_PIPE, LINUX_SYS_PIPE, "pipe"},
    {MACOS_SYS_MUNMAP, LINUX_SYS_MUNMAP, "munmap"},
    {MACOS_SYS_MPROTECT, LINUX_SYS_MPROTECT, "mprotect"},
    {MACOS_SYS_MADVISE, LINUX_SYS_MADVISE, "madvise"},
    {MACOS_SYS_MINCORE, LINUX_SYS_MINCORE, "mincore"},
    {MACOS_SYS_MSYNC, LINUX_SYS_MSYNC, "msync"},
    {MACOS_SYS_KILL, LINUX_SYS_KILL, "kill"},
    {MACOS_SYS_EXECVE, LINUX_SYS_EXECVE, "execve"},
    {MACOS_SYS_UMASK, LINUX_SYS_UMASK, "umask"},
    {MACOS_SYS_CHROOT, 161, "chroot"}, // Linux chroot is 161
    {MACOS_SYS_SYNC, 162, "sync"},     // Linux sync is 162
};

// Get syscall number for current platform
inline uint32_t get_syscall_number(const char* name, bool is_macos) {
    for (const auto& mapping : ESSENTIAL_SYSCALLS) {
        if (strcmp(mapping.name, name) == 0) {
            return is_macos ? mapping.macos_number : mapping.linux_number;
        }
    }
    return 0; // Unknown syscall
}

} // namespace SyscallConstants
