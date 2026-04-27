"""
AppArmor LSP – hover provider.

Provides rich Markdown documentation for:
 • Rule keywords (capability, network, signal, …)
 • Capabilities
 • Network families / types
 • File permission characters
 • AppArmor variables (@{HOME}, @{PROC}, …)
 • Profile flags
"""

from __future__ import annotations

import re
from typing import Optional

from lsprotocol.types import (
    Hover,
    MarkupContent,
    MarkupKind,
    Position,
    Range,
)

from .constants import (
    CAPABILITIES,
    DBUS_BUSES,
    FILE_PERMISSIONS,
    NETWORK_FAMILIES,
    NETWORK_TYPES,
    PROFILE_FLAGS,
    PTRACE_PERMISSIONS,
    SIGNAL_NAMES,
    VARIABLES,
)

# ── Word extraction ───────────────────────────────────────────────────────────

_RE_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RE_VAR  = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")
_RE_PERM = re.compile(r"(?<=[/\s])([rwaxmlkdDuUipPcCbBI]{1,4})(?=\s|,|$)")


def get_hover(
    line_text: str,
    position: Position,
) -> Optional[Hover]:
    """Return hover documentation for the word at the cursor."""
    ch = position.character

    # ── Variable hover ────────────────────────────────────────────────────
    for m in _RE_VAR.finditer(line_text):
        if m.start() <= ch <= m.end():
            var_name = "@{" + m.group(1) + "}"
            if var_name in VARIABLES:
                return _make_hover(
                    f"**`{var_name}`**\n\n{VARIABLES[var_name]}",
                    line_text, m.start(), m.end(),
                )

    # ── Word under cursor ─────────────────────────────────────────────────
    word, word_start, word_end = _word_at(line_text, ch)
    if not word:
        return None

    # Check capability
    if word in CAPABILITIES:
        return _make_hover(
            f"**Linux capability `{word}`** (`CAP_{word.upper()}`)\n\n"
            + _cap_doc(word),
            line_text, word_start, word_end,
        )

    # Check network family
    if word in NETWORK_FAMILIES:
        return _make_hover(
            f"**Network family `{word}`**\n\n"
            "Restricts network access to this address family.",
            line_text, word_start, word_end,
        )

    # Check network type
    if word in NETWORK_TYPES:
        return _make_hover(
            f"**Network socket type `{word}`**\n\n"
            "Restricts network access to this socket type.",
            line_text, word_start, word_end,
        )

    # Check keyword docs
    kw_doc = _KEYWORD_DOCS.get(word)
    if kw_doc:
        return _make_hover(kw_doc, line_text, word_start, word_end)

    # Check profile flags
    if word in PROFILE_FLAGS:
        return _make_hover(
            f"**Profile flag `{word}`**\n\n" + _flag_doc(word),
            line_text, word_start, word_end,
        )

    # Check signal names
    if word in SIGNAL_NAMES:
        return _make_hover(
            f"**Signal `{word.upper()}`**\n\nPOSIX signal name used in `signal` rules.",
            line_text, word_start, word_end,
        )

    # Check ptrace perms
    if word in PTRACE_PERMISSIONS:
        return _make_hover(
            f"**ptrace permission `{word}`**\n\n" + _ptrace_doc(word),
            line_text, word_start, word_end,
        )

    # ── Permission character hover ─────────────────────────────────────────
    # Look for a permission string adjacent to the cursor
    for pm in _RE_PERM.finditer(line_text):
        if pm.start() <= ch <= pm.end():
            perm_str = pm.group(1)
            lines_out = [f"**File permissions `{perm_str}`**\n"]
            for ch_perm in perm_str:
                desc = FILE_PERMISSIONS.get(ch_perm)
                if desc:
                    lines_out.append(f"- `{ch_perm}` — {desc}")
            return _make_hover(
                "\n".join(lines_out),
                line_text, pm.start(), pm.end(),
            )

    return None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _word_at(line: str, ch: int) -> tuple[str, int, int]:
    for m in _RE_WORD.finditer(line):
        if m.start() <= ch <= m.end():
            return m.group(), m.start(), m.end()
    return "", ch, ch


def _make_hover(md: str, line: str, start: int, end: int) -> Hover:
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=md),
        range=Range(
            start=Position(0, start),  # line offset is handled by caller
            end=Position(0, end),
        ),
    )


def _flag_doc(flag: str) -> str:
    docs = {
        "complain": "Log policy violations but do not enforce them. Useful for developing new profiles.",
        "enforce":  "Enforce the policy (default mode).",
        "kill":     "Kill processes that violate the policy.",
        "unconfined": "Run without any AppArmor confinement.",
        "prompt":   "Prompt the user on violations (requires a policy prompt responder).",
        "mediate_deleted": "Continue to mediate access after a file is deleted (unlinked).",
        "attach_disconnected": "Allow the profile to attach even when the binary has been disconnected from a dentry.",
        "chroot_relative": "Interpret paths relative to the process's chroot.",
        "debug":    "Enable debug logging for this profile.",
    }
    return docs.get(flag, "AppArmor profile flag.")


def _cap_doc(cap: str) -> str:
    docs = {
        "chown":          "Change file ownership (chown/fchown/lchown).",
        "dac_override":   "Bypass discretionary access control (DAC) checks.",
        "dac_read_search":"Bypass DAC read/search checks.",
        "fowner":         "Bypass permission checks on operations that normally require file ownership.",
        "fsetid":         "Don't clear set-user-ID/set-group-ID bits on file modification.",
        "kill":           "Send signals to any process.",
        "setgid":         "Change group ID (setgid/setegid).",
        "setuid":         "Change user ID (setuid/seteuid).",
        "setpcap":        "Modify process capability sets.",
        "net_bind_service":"Bind to privileged ports (below 1024).",
        "net_raw":        "Use raw/packet sockets.",
        "net_admin":      "Perform various network administration tasks.",
        "sys_chroot":     "Use chroot().",
        "sys_admin":      "A broad capability covering many system administration operations.",
        "sys_ptrace":     "Ptrace any process.",
        "sys_module":     "Load and unload kernel modules.",
        "sys_rawio":      "Raw I/O operations (ioperm, iopl, /dev/mem).",
        "sys_nice":       "Raise process priority, set CPU affinity, I/O scheduling class.",
        "sys_time":       "Set system clock.",
        "mknod":          "Create special files using mknod.",
        "audit_write":    "Write to the kernel audit log.",
        "audit_control":  "Control the kernel audit system.",
        "setfcap":        "Set file capabilities.",
        "mac_override":   "Override Mandatory Access Control.",
        "mac_admin":      "Administer Mandatory Access Control.",
        "syslog":         "Use privileged syslog operations.",
        "bpf":            "Load/manage BPF programs.",
        "perfmon":        "Monitor system performance.",
        "checkpoint_restore": "Checkpoint and restore processes.",
    }
    return docs.get(cap, "Linux capability — see `man 7 capabilities` for details.")


def _ptrace_doc(perm: str) -> str:
    docs = {
        "read":      "Allow reading the state of processes matched by `peer=`.",
        "readby":    "Allow the process to be read (introspected) by processes matched by `peer=`.",
        "trace":     "Allow full ptrace of processes matched by `peer=`.",
        "tracedby":  "Allow the process to be ptrace'd by processes matched by `peer=`.",
    }
    return docs.get(perm, "ptrace permission.")


# ── Keyword documentation ─────────────────────────────────────────────────────

_KEYWORD_DOCS: dict[str, str] = {
    "capability": (
        "## `capability`\n\n"
        "Grant one or more Linux capabilities to the confined process.\n\n"
        "```\ncapability net_bind_service, net_raw,\n```\n\n"
        "See `man 7 capabilities` for a full list."
    ),
    "network": (
        "## `network`\n\n"
        "Restrict network access by address family and/or socket type.\n\n"
        "```\nnetwork inet stream,\nnetwork inet6,\n```\n\n"
        "Omitting the family/type allows all network access."
    ),
    "signal": (
        "## `signal`\n\n"
        "Mediate sending and receiving of POSIX signals.\n\n"
        "```\nsignal (send) set=(term kill) peer=/usr/bin/myapp,\n```\n"
    ),
    "ptrace": (
        "## `ptrace`\n\n"
        "Control ptrace access between processes.\n\n"
        "```\nptrace (read trace) peer=/usr/bin/gdb,\n```\n"
    ),
    "mount": (
        "## `mount`\n\n"
        "Allow mounting a filesystem.\n\n"
        "```\nmount options=(ro, nodev) /dev/sda1 -> /mnt/data,\n```\n"
    ),
    "umount": (
        "## `umount`\n\n"
        "Allow unmounting a filesystem.\n\n"
        "```\numount /mnt/data,\n```\n"
    ),
    "dbus": (
        "## `dbus`\n\n"
        "Mediate D-Bus communication.\n\n"
        "```\ndbus send bus=system path=/org/freedesktop/NetworkManager\n"
        "     interface=org.freedesktop.NetworkManager member=GetDevices,\n```\n"
    ),
    "unix": (
        "## `unix`\n\n"
        "Mediate Unix domain socket access.\n\n"
        "```\nunix (connect) type=stream addr=@/tmp/.X11-unix/X0,\n```\n"
    ),
    "deny": (
        "## `deny`\n\n"
        "Explicitly deny an access, silencing audit messages (quiets the log).\n\n"
        "```\ndeny /etc/shadow r,\n```\n"
    ),
    "audit": (
        "## `audit`\n\n"
        "Allow but force an audit log entry for every access.\n\n"
        "```\naudit /tmp/** rw,\n```\n"
    ),
    "owner": (
        "## `owner`\n\n"
        "Apply the rule only when the process owns the file (UID match).\n\n"
        "```\nowner @{HOME}/** rw,\n```\n"
    ),
    "profile": (
        "## `profile`\n\n"
        "Define a named AppArmor profile or a sub-profile.\n\n"
        "```\nprofile myapp /usr/bin/myapp {\n  include <abstractions/base>\n  ...\n}\n```\n"
    ),
    "hat": (
        "## `hat`\n\n"
        "Define a hat — a sub-profile accessible via `change_hat()`.\n\n"
        "Used in multi-threaded applications (Apache mod_apparmor, etc.).\n"
    ),
    "include": (
        "## `include`\n\n"
        "Include another AppArmor policy file.\n\n"
        "```\ninclude <abstractions/base>\ninclude if exists <local/myapp>\n```\n"
    ),
    "rlimit": (
        "## `rlimit`\n\n"
        "Set a resource limit for the confined process.\n\n"
        "```\nrlimit nofile <= 1024,\nrlimit as <= 1G,\n```\n"
    ),
    "change_profile": (
        "## `change_profile`\n\n"
        "Allow the process to switch to a different AppArmor profile.\n\n"
        "```\nchange_profile -> /usr/bin/newapp,\n```\n"
    ),
    "change_hat": (
        "## `change_hat`\n\n"
        "Allow the process to switch to a hat sub-profile.\n\n"
        "```\nchange_hat myhat,\n```\n"
    ),
    "pivot_root": (
        "## `pivot_root`\n\n"
        "Allow a `pivot_root()` system call to change the filesystem root.\n"
    ),
    "complain": (
        "## `complain` (profile flag)\n\n"
        "Puts the profile in complain mode: violations are logged but not blocked.\n\n"
        "```\nprofile myapp flags=(complain) {\n  ...\n}\n```\n"
    ),
    "enforce": (
        "## `enforce` (profile flag)\n\n"
        "The default mode — violations are blocked and logged.\n"
    ),
    "userns": (
        "## `userns`\n\n"
        "Allow creation of user namespaces (requires AppArmor 4.x / kernel ≥ 6.7).\n\n"
        "```\nuserns,\n```\n"
    ),
    "io_uring": (
        "## `io_uring`\n\n"
        "Mediate io_uring operations.\n\n"
        "```\nio_uring (sqpoll override_creds),\n```\n"
    ),
    "mqueue": (
        "## `mqueue`\n\n"
        "Mediate POSIX and System V message queue operations.\n\n"
        "```\nmqueue (create open read write) type=posix name=/myqueue,\n```\n"
    ),
}
