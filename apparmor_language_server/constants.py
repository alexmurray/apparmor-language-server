"""
AppArmor LSP – constants: keywords, permissions, capabilities etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import chain, combinations

# ── KeywordDef ────────────────────────────────────────────────────────────────


@dataclass
class KeywordDef:
    """Unified definition for any AppArmor keyword, capability, flag, or permission.

    Attributes:
        doc:     Full Markdown documentation string, used verbatim by the hover
                 provider.  Should include a heading and example code block where
                 appropriate.
        detail:  Brief one-line description shown in the completion popup.  If
                 omitted the hover ``doc`` is used as-is for that context too.
        snippet: LSP snippet text (with ``${N:placeholder}`` syntax) inserted on
                 completion.  ``None`` means no snippet is provided for this
                 entry (plain-text label insertion is used instead).
    """

    doc: str
    detail: str = ""
    snippet: str | None = None


# ── Qualifiers  ───────────────────────────────────────────────────────────────

QUALIFIER_DEFS: dict[str, KeywordDef] = {
    "allow": KeywordDef(
        doc="**Qualifier `allow`**\n\nAllow the specified access.",
    ),
    "deny": KeywordDef(
        doc="**Qualifier `deny`**\n\nExplicitly deny the specified access.",
    ),
    "audit": KeywordDef(
        doc="**Qualifier `audit`**\n\nLog the specified access to the audit log.",
    ),
    "quiet": KeywordDef(
        doc="**Qualifier `quiet`**\n\nDon't log the specified access.",
    ),
}

QUALIFIERS: list[str] = list(QUALIFIER_DEFS.keys())

# ── Linux capabilities ────────────────────────────────────────────────────────
# Maps each capability name to its KeywordDef; doc is the full hover Markdown.
# CAPABILITIES (list) is derived below for backward compatibility.

CAPABILITY_DEFS: dict[str, KeywordDef] = {
    "audit_control": KeywordDef(
        doc="**Linux capability `audit_control`** (`CAP_AUDIT_CONTROL`)\n\nControl the kernel audit system.",
    ),
    "audit_read": KeywordDef(
        doc="**Linux capability `audit_read`** (`CAP_AUDIT_READ`)\n\nRead audit log via multicast netlink socket.",
    ),
    "audit_write": KeywordDef(
        doc="**Linux capability `audit_write`** (`CAP_AUDIT_WRITE`)\n\nWrite to the kernel audit log.",
    ),
    "block_suspend": KeywordDef(
        doc="**Linux capability `block_suspend`** (`CAP_BLOCK_SUSPEND`)\n\nPrevent system from suspending.",
    ),
    "bpf": KeywordDef(
        doc="**Linux capability `bpf`** (`CAP_BPF`)\n\nLoad/manage BPF programs.",
    ),
    "checkpoint_restore": KeywordDef(
        doc="**Linux capability `checkpoint_restore`** (`CAP_CHECKPOINT_RESTORE`)\n\nCheckpoint and restore processes.",
    ),
    "chown": KeywordDef(
        doc="**Linux capability `chown`** (`CAP_CHOWN`)\n\nChange file ownership (chown/fchown/lchown).",
    ),
    "dac_override": KeywordDef(
        doc="**Linux capability `dac_override`** (`CAP_DAC_OVERRIDE`)\n\nBypass discretionary access control (DAC) checks.",
    ),
    "dac_read_search": KeywordDef(
        doc="**Linux capability `dac_read_search`** (`CAP_DAC_READ_SEARCH`)\n\nBypass DAC read/search checks.",
    ),
    "fowner": KeywordDef(
        doc="**Linux capability `fowner`** (`CAP_FOWNER`)\n\nBypass permission checks on operations that normally require file ownership.",
    ),
    "fsetid": KeywordDef(
        doc="**Linux capability `fsetid`** (`CAP_FSETID`)\n\nDon't clear set-user-ID/set-group-ID bits on file modification.",
    ),
    "ipc_lock": KeywordDef(
        doc="**Linux capability `ipc_lock`** (`CAP_IPC_LOCK`)\n\nLock memory (mlock, mlockall, shmctl).",
    ),
    "ipc_owner": KeywordDef(
        doc="**Linux capability `ipc_owner`** (`CAP_IPC_OWNER`)\n\nBypass IPC object ownership checks.",
    ),
    "kill": KeywordDef(
        doc="**Linux capability `kill`** (`CAP_KILL`)\n\nSend signals to any process.",
    ),
    "lease": KeywordDef(
        doc="**Linux capability `lease`** (`CAP_LEASE`)\n\nEstablish leases on arbitrary files.",
    ),
    "linux_immutable": KeywordDef(
        doc="**Linux capability `linux_immutable`** (`CAP_LINUX_IMMUTABLE`)\n\nSet the FS_APPEND_FL and FS_IMMUTABLE_FL inode flags.",
    ),
    "mac_admin": KeywordDef(
        doc="**Linux capability `mac_admin`** (`CAP_MAC_ADMIN`)\n\nAdminister Mandatory Access Control.",
    ),
    "mac_override": KeywordDef(
        doc="**Linux capability `mac_override`** (`CAP_MAC_OVERRIDE`)\n\nOverride Mandatory Access Control.",
    ),
    "mknod": KeywordDef(
        doc="**Linux capability `mknod`** (`CAP_MKNOD`)\n\nCreate special files using mknod.",
    ),
    "net_admin": KeywordDef(
        doc="**Linux capability `net_admin`** (`CAP_NET_ADMIN`)\n\nPerform various network administration tasks.",
    ),
    "net_bind_service": KeywordDef(
        doc="**Linux capability `net_bind_service`** (`CAP_NET_BIND_SERVICE`)\n\nBind to privileged ports (below 1024).",
    ),
    "net_broadcast": KeywordDef(
        doc="**Linux capability `net_broadcast`** (`CAP_NET_BROADCAST`)\n\nMake socket broadcasts and listen to multicasts.",
    ),
    "net_raw": KeywordDef(
        doc="**Linux capability `net_raw`** (`CAP_NET_RAW`)\n\nUse raw/packet sockets.",
    ),
    "perfmon": KeywordDef(
        doc="**Linux capability `perfmon`** (`CAP_PERFMON`)\n\nMonitor system performance.",
    ),
    "setfcap": KeywordDef(
        doc="**Linux capability `setfcap`** (`CAP_SETFCAP`)\n\nSet file capabilities.",
    ),
    "setgid": KeywordDef(
        doc="**Linux capability `setgid`** (`CAP_SETGID`)\n\nChange group ID (setgid/setegid).",
    ),
    "setpcap": KeywordDef(
        doc="**Linux capability `setpcap`** (`CAP_SETPCAP`)\n\nModify process capability sets.",
    ),
    "setuid": KeywordDef(
        doc="**Linux capability `setuid`** (`CAP_SETUID`)\n\nChange user ID (setuid/seteuid).",
    ),
    "sys_admin": KeywordDef(
        doc="**Linux capability `sys_admin`** (`CAP_SYS_ADMIN`)\n\nA broad capability covering many system administration operations.",
    ),
    "sys_boot": KeywordDef(
        doc="**Linux capability `sys_boot`** (`CAP_SYS_BOOT`)\n\nUse reboot() and kexec_load().",
    ),
    "sys_chroot": KeywordDef(
        doc="**Linux capability `sys_chroot`** (`CAP_SYS_CHROOT`)\n\nUse chroot().",
    ),
    "sys_module": KeywordDef(
        doc="**Linux capability `sys_module`** (`CAP_SYS_MODULE`)\n\nLoad and unload kernel modules.",
    ),
    "sys_nice": KeywordDef(
        doc="**Linux capability `sys_nice`** (`CAP_SYS_NICE`)\n\nRaise process priority, set CPU affinity, I/O scheduling class.",
    ),
    "sys_pacct": KeywordDef(
        doc="**Linux capability `sys_pacct`** (`CAP_SYS_PACCT`)\n\nUse acct() to enable/disable process accounting.",
    ),
    "sys_ptrace": KeywordDef(
        doc="**Linux capability `sys_ptrace`** (`CAP_SYS_PTRACE`)\n\nPtrace any process.",
    ),
    "sys_rawio": KeywordDef(
        doc="**Linux capability `sys_rawio`** (`CAP_SYS_RAWIO`)\n\nRaw I/O operations (ioperm, iopl, /dev/mem).",
    ),
    "sys_resource": KeywordDef(
        doc="**Linux capability `sys_resource`** (`CAP_SYS_RESOURCE`)\n\nOverride resource limits.",
    ),
    "sys_time": KeywordDef(
        doc="**Linux capability `sys_time`** (`CAP_SYS_TIME`)\n\nSet system clock.",
    ),
    "sys_tty_config": KeywordDef(
        doc="**Linux capability `sys_tty_config`** (`CAP_SYS_TTY_CONFIG`)\n\nUse vhangup() and privileged ioctl()s on virtual terminals.",
    ),
    "syslog": KeywordDef(
        doc="**Linux capability `syslog`** (`CAP_SYSLOG`)\n\nUse privileged syslog operations.",
    ),
    "wake_alarm": KeywordDef(
        doc="**Linux capability `wake_alarm`** (`CAP_WAKE_ALARM`)\n\nTrigger system wakeup via CLOCK_REALTIME_ALARM or CLOCK_BOOTTIME_ALARM.",
    ),
}

# Derived list – kept for backward compatibility with code that imports CAPABILITIES.
CAPABILITIES: list[str] = list(CAPABILITY_DEFS.keys())

# ── Network ───────────────────────────────────────────────────────────────────

NETWORK_PERMISSIONS: list[str] = [
    "create",
    "accept",
    "bind",
    "connect",
    "listen",
    "read",
    "write",
    "send",
    "receive",
    "getsockname",
    "getpeername",
    "getsockopt",
    "setsockopt",
    "getattr",
    "setattr",
    "shutdown",
    "r",
    "w",
    "rw",
    "getopt",
    "setopt",
]

NETWORK_DOMAINS: list[str] = [
    "unix",
    "inet",
    "ax25",
    "ipx",
    "appletalk",
    "netrom",
    "bridge",
    "atmpvc",
    "x25",
    "inet6",
    "rose",
    "netbeui",
    "security",
    "key",
    "netlink",
    "packet",
    "ash",
    "econet",
    "atmsvc",
    "rds",
    "sna",
    "irda",
    "pppox",
    "wanpipe",
    "llc",
    "ib",
    "mpls",
    "can",
    "tipc",
    "bluetooth",
    "iucv",
    "rxrpc",
    "isdn",
    "phonet",
    "ieee802154",
    "caif",
    "alg",
    "nfc",
    "vsock",
    "kcm",
    "qipcrtr",
    "smc",
    "xdp",
    "mctp",
]

NETWORK_TYPES: list[str] = [
    "stream",
    "dgram",
    "seqpacket",
    "rdm",
    "raw",
    "packet",
]

NETWORK_PROTOCOLS: list[str] = [
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "raw",
]

# ── Unix socket ───────────────────────────────────────────────────────────────

UNIX_TYPES: list[str] = [
    "stream",
    "dgram",
    "seqpacket",
]

# ── Signal ────────────────────────────────────────────────────────────────────

SIGNAL_PERMISSIONS: list[str] = [
    "send",
    "receive",
    "read",
    "write",
    "r",
    "w",
    "rw",
]

SIGNAL_NAMES: list[str] = [
    "hup",
    "int",
    "quit",
    "ill",
    "trap",
    "abrt",
    "bus",
    "fpe",
    "kill",
    "usr1",
    "segv",
    "usr2",
    "pipe",
    "alrm",
    "term",
    "chld",
    "cont",
    "stop",
    "tstp",
    "stp",
    "ttin",
    "ttou",
    "urg",
    "xcpu",
    "xfsz",
    "vtalrm",
    "prof",
    "winch",
    "io",
    "pwr",
    "sys",
    "stkflt",
    "emt",
    "exists",
    "rtmin",
    "rtmax",
]

# ── Ptrace ────────────────────────────────────────────────────────────────────
# Maps each ptrace permission to its KeywordDef.
# PTRACE_PERMISSIONS (list) is derived below for backward compatibility.

PTRACE_DEFS: dict[str, KeywordDef] = {
    "read": KeywordDef(
        doc="**ptrace permission `read`**\n\nAllow reading the state of processes matched by `peer=`.",
    ),
    "readby": KeywordDef(
        doc="**ptrace permission `readby`**\n\nAllow the process to be read (introspected) by processes matched by `peer=`.",
    ),
    "trace": KeywordDef(
        doc="**ptrace permission `trace`**\n\nAllow full ptrace of processes matched by `peer=`.",
    ),
    "tracedby": KeywordDef(
        doc="**ptrace permission `tracedby`**\n\nAllow the process to be ptrace'd by processes matched by `peer=`.",
    ),
    "r": KeywordDef(
        doc="**ptrace permission `r`**\n\nShorthand for `read`. Allow reading the state of processes matched by `peer=`.",
    ),
    "w": KeywordDef(
        doc="**ptrace permission `w`**\n\nShorthand for `write`. Allow writing/tracing processes matched by `peer=`.",
    ),
    "rw": KeywordDef(
        doc="**ptrace permission `rw`**\n\nShorthand for read+write. Allow reading and tracing processes matched by `peer=`.",
    ),
}

# Derived list – kept for backward compatibility.
PTRACE_PERMISSIONS: list[str] = list(PTRACE_DEFS.keys())

# ── Mount ─────────────────────────────────────────────────────────────────────

MOUNT_OPTION_DEFS: dict[str, KeywordDef] = {
    "ro": KeywordDef(doc="**Mount option `ro`**\n\nMount read-only."),
    "rw": KeywordDef(doc="**Mount option `rw`**\n\nMount read-write."),
    "suid": KeywordDef(
        doc="**Mount option `suid`**\n\nAllow set-user-ID and set-group-ID bits to take effect."
    ),
    "nosuid": KeywordDef(
        doc="**Mount option `nosuid`**\n\nIgnore set-user-ID and set-group-ID bits."
    ),
    "dev": KeywordDef(doc="**Mount option `dev`**\n\nAllow access to device files."),
    "nodev": KeywordDef(
        doc="**Mount option `nodev`**\n\nDisallow access to device files."
    ),
    "exec": KeywordDef(
        doc="**Mount option `exec`**\n\nAllow execution of binaries on this filesystem."
    ),
    "noexec": KeywordDef(
        doc="**Mount option `noexec`**\n\nDisallow execution of binaries on this filesystem."
    ),
    "sync": KeywordDef(doc="**Mount option `sync`**\n\nAll I/O is done synchronously."),
    "async": KeywordDef(
        doc="**Mount option `async`**\n\nAll I/O is done asynchronously."
    ),
    "remount": KeywordDef(
        doc="**Mount option `remount`**\n\nRemount an already-mounted filesystem with new options."
    ),
    "mand": KeywordDef(doc="**Mount option `mand`**\n\nAllow mandatory file locking."),
    "nomand": KeywordDef(
        doc="**Mount option `nomand`**\n\nDisallow mandatory file locking."
    ),
    "dirsync": KeywordDef(
        doc="**Mount option `dirsync`**\n\nDirectory updates are written synchronously."
    ),
    "noatime": KeywordDef(
        doc="**Mount option `noatime`**\n\nDo not update file access times."
    ),
    "nodiratime": KeywordDef(
        doc="**Mount option `nodiratime`**\n\nDo not update directory access times."
    ),
    "bind": KeywordDef(
        doc="**Mount option `bind`**\n\nBind-mount — mirror a subtree at another location."
    ),
    "rbind": KeywordDef(doc="**Mount option `rbind`**\n\nRecursive bind-mount."),
    "move": KeywordDef(
        doc="**Mount option `move`**\n\nAtomically move a mount point to a new location."
    ),
    "silent": KeywordDef(
        doc="**Mount option `silent`**\n\nSuppress kernel messages for this mount."
    ),
    "acl": KeywordDef(doc="**Mount option `acl`**\n\nUse POSIX Access Control Lists."),
    "noacl": KeywordDef(
        doc="**Mount option `noacl`**\n\nDo not use POSIX Access Control Lists."
    ),
    "relatime": KeywordDef(
        doc="**Mount option `relatime`**\n\nUpdate access time only when it is older than the modify/change time."
    ),
    "iversion": KeywordDef(
        doc="**Mount option `iversion`**\n\nIncrement `i_version` on each modification."
    ),
    "noiversion": KeywordDef(
        doc="**Mount option `noiversion`**\n\nDo not increment `i_version`."
    ),
    "strictatime": KeywordDef(
        doc="**Mount option `strictatime`**\n\nAlways update access times (overrides `relatime`/`noatime`)."
    ),
    "lazytime": KeywordDef(
        doc="**Mount option `lazytime`**\n\nLazily flush timestamp updates to disk."
    ),
    "nolazytime": KeywordDef(
        doc="**Mount option `nolazytime`**\n\nDo not use lazy timestamp updates."
    ),
    "unbindable": KeywordDef(
        doc="**Mount option `unbindable`**\n\nMake this mount unbindable (cannot be bind-mounted)."
    ),
    "runbindable": KeywordDef(
        doc="**Mount option `runbindable`**\n\nRecursively unbindable."
    ),
    "private": KeywordDef(
        doc="**Mount option `private`**\n\nDo not propagate mount events to or from peers."
    ),
    "rprivate": KeywordDef(doc="**Mount option `rprivate`**\n\nRecursively private."),
    "shared": KeywordDef(
        doc="**Mount option `shared`**\n\nPropagate mount events to peer mounts."
    ),
    "rshared": KeywordDef(doc="**Mount option `rshared`**\n\nRecursively shared."),
    "slave": KeywordDef(
        doc="**Mount option `slave`**\n\nReceive propagation from master but do not propagate back."
    ),
    "rslave": KeywordDef(doc="**Mount option `rslave`**\n\nRecursively slave."),
    "atime": KeywordDef(
        doc="**Mount option `atime`**\n\nUpdate access times on reads."
    ),
    "diratime": KeywordDef(
        doc="**Mount option `diratime`**\n\nUpdate directory access times."
    ),
    "verbose": KeywordDef(
        doc="**Mount option `verbose`**\n\nEnable verbose mount output."
    ),
    "loud": KeywordDef(
        doc="**Mount option `loud`**\n\nAlias for `verbose`; enable verbose mount output."
    ),
    "norelatime": KeywordDef(
        doc="**Mount option `norelatime`**\n\nDisable relative access time updates."
    ),
    "nostrictatime": KeywordDef(
        doc="**Mount option `nostrictatime`**\n\nDisable strict access time updates."
    ),
    "nouser": KeywordDef(
        doc="**Mount option `nouser`**\n\nOnly root may mount the filesystem."
    ),
    "user": KeywordDef(
        doc="**Mount option `user`**\n\nAllow an ordinary user to mount the filesystem."
    ),
    "symfollow": KeywordDef(
        doc="**Mount option `symfollow`**\n\nFollow symbolic links during mount resolution."
    ),
    "nosymfollow": KeywordDef(
        doc="**Mount option `nosymfollow`**\n\nDo not follow symbolic links during mount resolution."
    ),
}

MOUNT_OPTIONS: list[str] = list(MOUNT_OPTION_DEFS.keys())

# ── Resource limits ───────────────────────────────────────────────────────────

RLIMIT_DEFS: dict[str, KeywordDef] = {
    "cpu": KeywordDef(doc="**Resource limit `cpu`**\n\nCPU time limit (seconds)."),
    "fsize": KeywordDef(doc="**Resource limit `fsize`**\n\nMaximum file size (bytes)."),
    "data": KeywordDef(
        doc="**Resource limit `data`**\n\nMaximum data segment size (bytes)."
    ),
    "stack": KeywordDef(
        doc="**Resource limit `stack`**\n\nMaximum stack size (bytes)."
    ),
    "core": KeywordDef(
        doc="**Resource limit `core`**\n\nMaximum core dump file size (bytes)."
    ),
    "rss": KeywordDef(
        doc="**Resource limit `rss`**\n\nMaximum resident set size (bytes)."
    ),
    "nofile": KeywordDef(
        doc="**Resource limit `nofile`**\n\nMaximum number of open file descriptors."
    ),
    "ofile": KeywordDef(doc="**Resource limit `ofile`**\n\nAlias for `nofile`."),
    "as": KeywordDef(
        doc="**Resource limit `as`**\n\nMaximum virtual address space size (bytes)."
    ),
    "nproc": KeywordDef(
        doc="**Resource limit `nproc`**\n\nMaximum number of processes."
    ),
    "memlock": KeywordDef(
        doc="**Resource limit `memlock`**\n\nMaximum locked-in-memory address space (bytes)."
    ),
    "locks": KeywordDef(
        doc="**Resource limit `locks`**\n\nMaximum number of file locks."
    ),
    "sigpending": KeywordDef(
        doc="**Resource limit `sigpending`**\n\nMaximum number of queued signals."
    ),
    "msgqueue": KeywordDef(
        doc="**Resource limit `msgqueue`**\n\nMaximum bytes in POSIX message queues."
    ),
    "nice": KeywordDef(
        doc="**Resource limit `nice`**\n\nCeiling on the process's nice level."
    ),
    "rtprio": KeywordDef(
        doc="**Resource limit `rtprio`**\n\nMaximum real-time scheduling priority."
    ),
    "rttime": KeywordDef(
        doc="**Resource limit `rttime`**\n\nTimeout for real-time tasks without a blocking syscall (microseconds)."
    ),
}

RLIMIT_TYPES: list[str] = list(RLIMIT_DEFS.keys())

# ── DBus ──────────────────────────────────────────────────────────────────────

DBUS_PERMISSION_DEFS: dict[str, KeywordDef] = {
    "send": KeywordDef(
        doc="**D-Bus permission `send`**\n\nAllow sending D-Bus messages."
    ),
    "receive": KeywordDef(
        doc="**D-Bus permission `receive`**\n\nAllow receiving D-Bus messages."
    ),
    "bind": KeywordDef(
        doc="**D-Bus permission `bind`**\n\nAllow binding a well-known D-Bus service name."
    ),
    "eavesdrop": KeywordDef(
        doc="**D-Bus permission `eavesdrop`**\n\nAllow eavesdropping on all D-Bus messages (requires privileged bus config)."
    ),
    "r": KeywordDef(
        doc="**D-Bus permission `r`**\n\nShorthand for `read` — allow receiving D-Bus messages."
    ),
    "w": KeywordDef(
        doc="**D-Bus permission `w`**\n\nShorthand for `write` — allow sending D-Bus messages."
    ),
    "rw": KeywordDef(
        doc="**D-Bus permission `rw`**\n\nShorthand for `read write` — allow sending and receiving."
    ),
    "read": KeywordDef(
        doc="**D-Bus permission `read`**\n\nAllow reading (receiving) D-Bus messages."
    ),
    "write": KeywordDef(
        doc="**D-Bus permission `write`**\n\nAllow writing (sending) D-Bus messages."
    ),
}

DBUS_PERMISSIONS: list[str] = list(DBUS_PERMISSION_DEFS.keys())

DBUS_BUS_DEFS: dict[str, KeywordDef] = {
    "system": KeywordDef(
        doc="**D-Bus bus `system`**\n\nThe system-wide D-Bus message bus (`/run/dbus/system_bus_socket`)."
    ),
    "session": KeywordDef(
        doc="**D-Bus bus `session`**\n\nThe per-user D-Bus session bus."
    ),
}

DBUS_BUSES: list[str] = list(DBUS_BUS_DEFS.keys())

# ── io_uring ──────────────────────────────────────────────────────────────────

IO_URING_PERMISSION_DEFS: dict[str, KeywordDef] = {
    "sqpoll": KeywordDef(
        doc="**io_uring permission `sqpoll`**\n\nAllow use of `IORING_SETUP_SQPOLL` (kernel submission-queue polling thread)."
    ),
    "override_creds": KeywordDef(
        doc="**io_uring permission `override_creds`**\n\nAllow overriding credentials for io_uring operations."
    ),
    "cmd": KeywordDef(
        doc="**io_uring permission `cmd`**\n\nAllow `IORING_OP_URING_CMD` socket operations."
    ),
}

# ── mqueue ────────────────────────────────────────────────────────────────────

MQUEUE_PERMISSION_DEFS: dict[str, KeywordDef] = {
    "create": KeywordDef(
        doc="**mqueue permission `create`**\n\nCreate a new message queue."
    ),
    "open": KeywordDef(
        doc="**mqueue permission `open`**\n\nOpen an existing message queue."
    ),
    "delete": KeywordDef(
        doc="**mqueue permission `delete`**\n\nDelete (unlink) a message queue."
    ),
    "read": KeywordDef(
        doc="**mqueue permission `read`**\n\nRead messages from the queue."
    ),
    "write": KeywordDef(
        doc="**mqueue permission `write`**\n\nWrite messages to the queue."
    ),
    "getattr": KeywordDef(
        doc="**mqueue permission `getattr`**\n\nGet message queue attributes."
    ),
    "setattr": KeywordDef(
        doc="**mqueue permission `setattr`**\n\nSet message queue attributes."
    ),
    "r": KeywordDef(doc="**mqueue permission `r`**\n\nShorthand for `read`."),
    "w": KeywordDef(doc="**mqueue permission `w`**\n\nShorthand for `write`."),
    "rw": KeywordDef(doc="**mqueue permission `rw`**\n\nShorthand for read+write."),
}

## ── Keyword definitions ───────────────────────────────────────────────────────
# Single source of truth for hover docs, completion snippets, and brief details.

KEYWORD_DEFS: dict[str, KeywordDef] = {
    "alias": KeywordDef(
        doc=(
            "## `alias`\n\n"
            "Define an alias for a file path.\n\n"
            "```\nalias /usr/ -> /mnt/usr/,\n```\n"
        ),
        detail="Define an alias for a file path.",
        snippet="alias ${1:/path/} -> ${2:/other/},",
    ),
    "file": KeywordDef(
        doc=(
            "## `file`\n\n"
            "Mediate file access by path and permission.\n\n"
            "```\n/etc/passwd r,\nfile rw /var/log/**,\n```\n\n"
        ),
        detail="Mediate file access by path and permission.",
        snippet="file ${1:rwx} ${2:/path/},",
    ),
    "capability": KeywordDef(
        doc=(
            "## `capability`\n\n"
            "Grant one or more Linux capabilities to the confined process.\n\n"
            "```\ncapability net_bind_service, net_raw,\n```\n\n"
            "See `man 7 capabilities` for a full list."
        ),
        detail="Grant a Linux capability to the confined process.",
        snippet="capability ${1|" + ", ".join(CAPABILITIES) + "|},",
    ),
    "network": KeywordDef(
        doc=(
            "## `network`\n\n"
            "Restrict network access by address family and/or socket type.\n\n"
            "```\nnetwork inet stream,\nnetwork inet6,\n```\n\n"
            "Omitting the family/type allows all network access."
        ),
        detail="Allow network access for the given family/type.",
        snippet="network ${1|"
        + ", ".join(NETWORK_DOMAINS)
        + "|} ${2|"
        + ", ".join(NETWORK_TYPES)
        + "|},",
    ),
    "signal": KeywordDef(
        doc=(
            "## `signal`\n\n"
            "Mediate sending and receiving of POSIX signals.\n\n"
            "```\nsignal (send) set=(term kill) peer=/usr/bin/myapp,\n```\n"
        ),
        detail="Allow sending/receiving signals.",
        snippet="signal (${1|"
        + ", ".join(SIGNAL_PERMISSIONS)
        + "|}) set=(${2|"
        + ", ".join(SIGNAL_NAMES)
        + "|}) peer=${3:@{profile_name}},",
    ),
    "ptrace": KeywordDef(
        doc=(
            "## `ptrace`\n\n"
            "Control ptrace access between processes.\n\n"
            "```\nptrace (read trace) peer=/usr/bin/gdb,\n```\n"
        ),
        detail="Allow ptrace of another process.",
        snippet="ptrace (${1|"
        + ",".join(PTRACE_PERMISSIONS)
        + "|}) peer=${2:@{profile_name}},",
    ),
    "mount": KeywordDef(
        doc=(
            "## `mount`\n\n"
            "Allow mounting a filesystem.\n\n"
            "```\nmount options=(ro, nodev) /dev/sda1 -> /mnt/data,\n```\n"
        ),
        detail="Allow a mount operation.",
        snippet="mount options=(${1|"
        + ",".join(MOUNT_OPTIONS)
        + "|}) ${2:/path/} -> ${3:/mnt/},",
    ),
    "umount": KeywordDef(
        doc="## `umount`\n\nAllow unmounting a filesystem.\n\n```\numount /mnt/data,\n```\n",
        detail="Allow unmounting a filesystem.",
        snippet="umount ${1:/mnt/},",
    ),
    "dbus": KeywordDef(
        doc=(
            "## `dbus`\n\n"
            "Mediate D-Bus communication.\n\n"
            "```\ndbus send bus=system path=/org/freedesktop/NetworkManager\n"
            "     interface=org.freedesktop.NetworkManager member=GetDevices,\n```\n"
        ),
        detail="Allow DBus interaction.",
        snippet="dbus (${1|"
        + ",".join(DBUS_PERMISSIONS)
        + "|}) bus=${2|"
        + ",".join(DBUS_BUSES)
        + "|} path=${3:/org/example} interface=${4:org.example.Interface},",
    ),
    "unix": KeywordDef(
        doc=(
            "## `unix`\n\n"
            "Mediate Unix domain socket access.\n\n"
            "```\nunix (connect) type=stream addr=@/tmp/.X11-unix/X0,\n```\n"
        ),
        detail="Allow Unix domain socket operation.",
        snippet="unix (${1|"
        + ",".join(NETWORK_PERMISSIONS)
        + "|}) type=${2|"
        + ",".join(UNIX_TYPES)
        + "|} addr=${3:@path} peer=${4:(label=/foo,addr=@bar)},",
    ),
    "profile": KeywordDef(
        doc=(
            "## `profile`\n\n"
            "Define a named AppArmor profile or a sub-profile.\n\n"
            "```\nprofile myapp /usr/bin/myapp {\n  include <abstractions/base>\n  ...\n}\n```\n"
        ),
        detail="Define a new AppArmor profile.",
        snippet="profile ${1:name} ${2:/attachment} {\n  include <abstractions/base>\n  $0\n}",
    ),
    "hat": KeywordDef(
        doc=(
            "## `hat`\n\n"
            "Define a hat - a sub-profile accessible via `change_hat()`.\n\n"
            "Used in multi-threaded applications (Apache mod_apparmor, etc.).\n"
        ),
        detail="Define a hat (change_hat target) sub-profile.",
        snippet="hat ${1:name} {\n  $0\n}",
    ),
    "abi": KeywordDef(
        doc=(
            "## `abi`\n\n"
            "Set the ABI of this AppArmor policy file.\n\n"
            "```\nabi <abi/5.0>,\n```\n"
        ),
        detail="The AppArmor ABI to target for this profile.",
        snippet="abi <${1:abi/5.0}>,",
    ),
    "include": KeywordDef(
        doc=(
            "## `include`\n\n"
            "Include another AppArmor policy file.\n\n"
            "```\ninclude <abstractions/base>\n```\n"
        ),
        detail="Include an AppArmor abstraction or sub-policy file.",
        snippet="include <${1:abstractions/base}>",
    ),
    "include if exists": KeywordDef(
        doc=(
            "## `include if exists`\n\n"
            "Include another AppArmor policy file that may or may not exist.\n\n"
            "```\ninclude if exists <local/myapp>\n```\n"
        ),
        detail="Conditionally include a policy file if it exists.",
        snippet="include if exists <${1:local/myapp}>",
    ),
    "set rlimit": KeywordDef(
        doc=(
            "## `set rlimit`\n\n"
            "Set a resource limit for the confined process.\n\n"
            "```\nset rlimit nofile <= 1024,\nset rlimit as <= 1G,\n```\n"
        ),
        detail="Set a resource limit for the confined process.",
        snippet="set rlimit ${1|" + ",".join(RLIMIT_TYPES) + "|} <= ${2:1024},",
    ),
    "change_profile": KeywordDef(
        doc=(
            "## `change_profile`\n\n"
            "Allow the process to switch to a different AppArmor profile.\n\n"
            "```\nchange_profile -> /usr/bin/newapp,\n```\n"
        ),
        detail="Allow switching to another AppArmor profile.",
        snippet="change_profile -> ${1:profile_name},",
    ),
    "change_hat": KeywordDef(
        doc=(
            "## `change_hat`\n\n"
            "Allow the process to switch to a hat sub-profile.\n\n"
            "```\nchange_hat myhat,\n```\n"
        ),
        detail="Allow switching to a hat sub-profile.",
    ),
    "pivot_root": KeywordDef(
        doc=(
            "## `pivot_root`\n\n"
            "Allow a `pivot_root()` system call to change the filesystem root.\n"
        ),
        detail="Allow a pivot_root() system call.",
    ),
    "userns": KeywordDef(
        doc=(
            "## `userns`\n\n"
            "Allow creation of user namespaces (requires AppArmor 4.x / kernel ≥ 6.7).\n\n"
            "```\nuserns,\n```\n"
        ),
        detail="Allow user namespace creation.",
        snippet="userns,",
    ),
    "io_uring": KeywordDef(
        doc=(
            "## `io_uring`\n\n"
            "Mediate io_uring operations.\n\n"
            "```\nio_uring (sqpoll override_creds),\n```\n"
        ),
        detail="Allow io_uring operations.",
        snippet="io_uring (${1:sqpoll override_creds}),",
    ),
    "mqueue": KeywordDef(
        doc=(
            "## `mqueue`\n\n"
            "Mediate POSIX and System V message queue operations.\n\n"
            "```\nmqueue (create open read write) type=posix name=/myqueue,\n```\n"
        ),
        detail="Allow POSIX/SysV message queue operations.",
        snippet=(
            "mqueue (${1:create open delete read write})"
            " type=${2:posix} name=${3:/name},"
        ),
    ),
    "link": KeywordDef(
        doc=(
            "## `link`\n\n"
            "Allow creating a hard link.\n\n"
            "```\nlink /link -> /target,\nlink subset /foo -> /**,\n```\n\n"
            "The `subset` option requires that the permissions on the link are a subset of the target's permissions.\n"
        ),
        detail="Allow creating a hard link.",
        snippet="link ${1:/link} -> ${2:/target},",
    ),
    "all": KeywordDef(
        doc=(
            "## `all`\n\n"
            "Allow all access. Grants every permission for every resource type.\n\n"
            "```\nall,\n```\n"
        ),
        detail="Allow all access.",
        snippet="all,",
    ),
    "remount": KeywordDef(
        doc=(
            "## `remount`\n\n"
            "Allow remounting an already-mounted filesystem with new options.\n\n"
            "```\nremount options=(ro,nodev) /mnt/data,\n```\n"
        ),
        detail="Allow remounting a filesystem with new options.",
        snippet="remount ${1:/mnt/},",
    ),
}

# ── File permissions ──────────────────────────────────────────────────────────

FILE_PERMISSIONS: dict[str, str] = {
    "r": "Read",
    "w": "Write (conflicts with append)",
    "a": "Append (conflicts with write)",
    "m": "Memory-map executable (mmap PROT_EXEC)",
    "l": "Hard-link",
    "k": "Lock (fcntl and flock)",
    "x": "Execute (only valid for a deny rule with the deny qualifier)",
}

EXECUTE_PERMISSIONS: dict[str, str] = {
    # Execute modifiers
    "ix": "Execute and inherit current profile",
    "ux": "Execute unconfined (unsafe – no child profile)",
    "Ux": "Execute unconfined (safe – sanitise environment)",
    "px": "Execute under a named profile (requires matching profile)",
    "Px": "Execute under named profile (safe – sanitise environment)",
    "cx": "Execute under a child profile",
    "Cx": "Execute under child profile (safe)",
    "pix": "Execute under named profile or inherit",
    "Pix": "Execute under named profile (safe) or inherit",
    "cix": "Execute under child profile or inherit",
    "Cix": "Execute under child profile (safe) or inherit",
    "pux": "Execute under named profile or unconfined",
    "PUx": "Execute under named profile (safe) or unconfined",
    "cux": "Execute under child profile or unconfined",
    "CUx": "Execute under child profile (safe) or unconfined",
}

RE_FILE_PERMISSIONS = re.compile(
    r"(("
    # sort keys so we use the longest match first (e.g. "a" vs "append")
    + "|".join(
        [
            str(perm)
            for perm in sorted(
                FILE_PERMISSIONS.keys() | EXECUTE_PERMISSIONS.keys(),
                key=len,
                reverse=True,
            )
        ]
    )
    + ")+)"
)

# Every valid AppArmor permission combination:
#   - file_flags : any subset of FILE_PERMISSIONS
#   - exec_flag  : zero or one EXECUTE_PERMISSIONS  (16 choices)
#   - at least one of the above must be present
_exec_options = [(None, None), *EXECUTE_PERMISSIONS.items()]
_powerset = chain.from_iterable(
    combinations(FILE_PERMISSIONS, r) for r in range(len(FILE_PERMISSIONS) + 1)
)

PERMISSION_COMBINATIONS: dict[str, str] = {
    "".join(file_flags) + (exec_flag or ""): ";".join(
        [FILE_PERMISSIONS[f] for f in file_flags] + ([exec_desc] if exec_desc else [])
    )
    for file_flags in _powerset
    for exec_flag, exec_desc in _exec_options
    if file_flags or exec_flag is not None
}

# ── Profile flags ─────────────────────────────────────────────────────────────
# Maps each flag name to its KeywordDef.
# PROFILE_FLAGS (list) is derived below for backward compatibility.

FLAG_DEFS: dict[str, KeywordDef] = {
    "complain": KeywordDef(
        doc="**Profile flag `complain`**\n\nLog policy violations but do not enforce them. Useful for developing new profiles.",
    ),
    "enforce": KeywordDef(
        doc="**Profile flag `enforce`**\n\nEnforce the policy (default mode).",
    ),
    "kill": KeywordDef(
        doc="**Profile flag `kill`**\n\nKill processes that violate the policy.",
    ),
    "unconfined": KeywordDef(
        doc="**Profile flag `unconfined`**\n\nRun without any AppArmor confinement.",
    ),
    "prompt": KeywordDef(
        doc="**Profile flag `prompt`**\n\nPrompt the user on violations (requires a policy prompt responder).",
    ),
    "mediate_deleted": KeywordDef(
        doc="**Profile flag `mediate_deleted`**\n\nContinue to mediate access after a file is deleted (unlinked).",
    ),
    "attach_disconnected": KeywordDef(
        doc="**Profile flag `attach_disconnected`**\n\nAllow the profile to attach even when the binary has been disconnected from a dentry.",
    ),
    "attach_disconnected.path": KeywordDef(
        doc="**Profile flag `attach_disconnected.path`**\n\nSpecify the path used when `attach_disconnected` is active.",
    ),
    "chroot_relative": KeywordDef(
        doc="**Profile flag `chroot_relative`**\n\nInterpret paths relative to the process's chroot.",
    ),
    "debug": KeywordDef(
        doc="**Profile flag `debug`**\n\nEnable debug logging for this profile.",
    ),
    "interruptible": KeywordDef(
        doc="**Profile flag `interruptible`**\n\nAllow the profile to be interrupted.",
    ),
    "no_attach_disconnected": KeywordDef(
        doc="**Profile flag `no_attach_disconnected`**\n\nDisable attach_disconnected behaviour.",
    ),
    "default_allow": KeywordDef(
        doc="**Profile flag `default_allow`**\n\nChange the default behaviour from deny to allow. Operations not covered by a rule will be allowed (similar to unconfined but allow/deny rules still apply).",
    ),
    "audit": KeywordDef(
        doc="**Profile flag `audit`**\n\nCauses all operations, whether allowed or denied, to be logged to the audit system.",
    ),
    "attach_disconnected.ipc": KeywordDef(
        doc="**Profile flag `attach_disconnected.ipc`**\n\nA subset of attach_disconnected specific to IPC namespaces. Allows attaching disconnected POSIX mqueue paths without having to allow all disconnected files.",
    ),
    "kill.signal": KeywordDef(
        doc="**Profile flag `kill.signal`**\n\nSpecify the signal sent by AppArmor when in kill mode (e.g. `kill.signal=kill`). Format: `kill.signal=SIGNAL`.",
    ),
    "error": KeywordDef(
        doc="**Profile flag `error`**\n\nChange the error code returned on a policy violation (e.g. `error=EPERM`). Format: `error=ERRORCODE`.",
    ),
}

# Derived list – kept for backward compatibility.
PROFILE_FLAGS: list[str] = list(FLAG_DEFS.keys())

# ── Indentation used by the formatter ────────────────────────────────────────

DEFAULT_INDENT = "  "  # two spaces
