# AppArmor Language Server (`apparmor-language-server`)

[![CI](https://github.com/alexmurray/apparmor-language-server/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/alexmurray/apparmor-language-server/actions/workflows/build-and-test.yml)

A full-featured [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
server for editing **AppArmor profiles**, written in Python using
[pygls](https://github.com/openlawlibrary/pygls).

---

## Features

| Feature | Details |
|---|---|
| **Completion** | Rule keywords with snippets, all Linux capabilities, network families/types, signal names, ptrace/mount/dbus/unix permissions, file permission strings (`r`, `rw`, `rix`, `rPx`, …), `@{variable}` names, `#include` abstraction paths, live filesystem path completion |
| **Hover** | Rich Markdown docs for every keyword, capability, permission char, network family, profile flag and variable |
| **Goto Definition** | Jump from `#include <…>` or `include <…>` to the target file; jump to profile definitions by name |
| **Document Symbols** | Full outline: all profiles, hats, capabilities, file rules, includes and variables |
| **Workspace Symbols** | Search profiles across all open documents |
| **Diagnostics / Linting** | Unknown capabilities, network families/types, signal permissions/names, ptrace permissions, dbus permissions, unix socket types/permissions, mqueue types/permissions, io_uring permissions, userns permissions, mount options, rlimit resources/values; dangerous unconfined exec (`ux`/`Ux`/`pux`/`PUx`/`cux`/`CUx`); conflicting profile mode flags; invalid `flags=(error=…)` errno values; empty profiles; duplicate and conflicting capabilities; conflicting `allow`+`deny`; undefined variables and bool variables; missing `include`/`abi` targets; unclosed profiles; mutually exclusive file permissions (`w`+`a`); multiple exec transition modes; exec target without exec transition; exec transition with `deny`; bare `x` without `deny`; relative `alias` paths; `pivot_root` paths without trailing `/`; `network netlink` restricted to `dgram`/`raw`; also surfaces errors from `apparmor_parser` itself when available (skipped automatically for abstraction and tunables files) |
| **Formatting** | Normalise indentation, remove trailing whitespace, sort capabilities alphabetically, sort parenthesised lists, ensure trailing commas on all rules, normalise `#include` → `include`, collapse multiple blank lines |
| **Range Formatting** | Format a selected region only |
| **References** | Find all references to the identifier or variable under the cursor across all open documents (excludes path components and comments) |
| **Document Highlight** | Highlight all occurrences of the word under the cursor |

---

## Installation

### Prerequisites

- Python ≥ 3.10
- `pip`

### From source

```bash
git clone https://github.com/alexmurray/apparmor-language-server
cd apparmor-language-server
pip install .
```

Or install dependencies directly without building a package:

```bash
pip install pygls lsprotocol
python -m apparmor_language_server          # stdio mode
python -m apparmor_language_server --tcp    # TCP mode on 127.0.0.1:2087
```

---

## Running the server

### stdio (default — used by most editors)

```bash
apparmor-language-server
# or
python -m apparmor_language_server
```

### TCP (useful for debugging)

```bash
apparmor-language-server --tcp --host 127.0.0.1 --port 2087
```

---

## Standalone linter (`apparmor-lint`)

The package also ships a `apparmor-lint` command-line tool that runs the
**same parser and diagnostic checks** as the language server — useful in CI,
pre-commit hooks, or when you just want a quick check from the shell without
firing up an editor.

```bash
# Lint one or more files
apparmor-lint /etc/apparmor.d/usr.bin.foo
apparmor-lint profile.aa another-profile.aa

# Read from stdin
cat profile.aa | apparmor-lint -

# Skip the external apparmor_parser cross-check
apparmor-lint --no-parser profile.aa

# Machine-readable output for CI
apparmor-lint --format json profile.aa
```

### Output format

The default `pretty` format is GCC-compatible so editors and tools that
already parse `cc(1)` output (Vim quickfix, Emacs `compile`, `grep -nH`, …)
work out of the box:

```
profile.aa:3:3: error: Unknown capability 'bad_cap_xyz'. … [unknown-capability] (apparmor-language-server)
profile.aa:5:3: error: Network rule: netlink may only specify type 'dgram' or 'raw' (got 'stream'). [netlink-type-restricted] (apparmor-language-server)
```

`--format json` emits an array of records, each with `path`, `uri`,
`severity`, `message`, `code`, `source`, `line`, `column`, `end_line`,
and `end_column` — handy for piping into `jq` or aggregating across files.

### Options

| Flag | Meaning |
|---|---|
| `paths…` | One or more files to lint, or `-` to read from stdin |
| `--no-parser` | Skip the external `apparmor_parser -Q -K` cross-check |
| `--apparmor-parser PATH` | Use a specific `apparmor_parser` binary (default: `$PATH` lookup) |
| `-I DIR`, `--include-path DIR` | Extra directory to search for `include`/`abi` targets (repeatable) |
| `--format {pretty,json}` | Output format (default: `pretty`) |
| `-q`, `--quiet` | Only show error-severity diagnostics |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no error-severity diagnostics (warnings, info, hints permitted) |
| `1` | At least one error-severity diagnostic was emitted |
| `2` | The CLI itself could not run (file missing, argument is a directory, etc.) |

### Library API

`apparmor_language_server.lint` also exposes the linter as a Python API for
embedding in other tools:

```python
from apparmor_language_server.lint import lint_file, lint_text

# Returns dict[str, list[lsprotocol.types.Diagnostic]] keyed by URI.
diags = lint_file(Path("profile.aa"), run_apparmor_parser=False)
diags = lint_text("profile x { /foo r, }\n")
```

---

## Server configuration

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `APPARMOR_LSP_LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### LSP workspace settings

These are passed to the server via the standard LSP
`workspace/didChangeConfiguration` notification, nested under the
`apparmor` key.  How you set them depends on your editor (see the
examples below each editor section).

| Setting | Type | Default | Effect |
|---|---|---|---|
| `apparmor.diagnostics.enable` | boolean | `true` | Enable or disable all diagnostic (linting) checks |
| `apparmor.baseDir` | string | `"/etc/apparmor.d"` | Base directory for AppArmor profiles. Passed as `--base` to `apparmor_parser`. Also used as the default value for `apparmor.includeSearchPaths` when that setting is not configured. Defaults to `/var/lib/snapd/hostfs/etc/apparmor.d` when running as a snap. |
| `apparmor.parserConfigFile` | string | `""` | Path to the `apparmor_parser` configuration file, passed as `--config-file`. Leave empty to auto-detect: under snap confinement the host `/etc/apparmor/parser.conf` is used automatically; outside snap no `--config-file` is passed. |
| `apparmor.includeSearchPaths` | string[] | `[]` | Extra directories to search when resolving `include` and `abi` paths, prepended ahead of `apparmor.baseDir`. When empty, `apparmor.baseDir` is used as the sole search directory. |
| `apparmor.profilesSubdir` | string | `"apparmor.d"` | Subdirectory of the workspace root to index for workspace symbols; set to `""` or `"."` to index the whole workspace |
| `apparmor.apparmorParserPath` | string | `""` | Path to the `apparmor_parser` binary. Leave empty to auto-detect from `$PATH`. Set to a specific path (e.g. `/usr/sbin/apparmor_parser`) to pin a particular version. When the binary is found, the server runs `apparmor_parser -Q -K` against each saved profile file and surfaces any errors as diagnostics. Files with no top-level profiles (abstractions, tunables, ABI files) are skipped automatically. |

---

## Editor configuration

### Neovim (with `nvim-lspconfig`)

```lua
-- In your init.lua or a plugin file
local lspconfig = require('lspconfig')
local configs   = require('lspconfig.configs')

-- Register the server if it is not already known
if not configs.apparmor_language_server then
  configs.apparmor_language_server = {
    default_config = {
      cmd         = { 'apparmor-language-server' },  -- or { 'python', '-m', 'apparmor_language_server' }
      filetypes   = { 'apparmor' },
      root_dir    = lspconfig.util.root_pattern('.git', '/etc/apparmor.d'),
      single_file_support = true,
      settings    = {},
    },
  }
end

lspconfig.apparmor_language_server.setup({
  on_attach = function(client, bufnr)
    -- Enable format-on-save
    vim.api.nvim_create_autocmd('BufWritePre', {
      buffer = bufnr,
      callback = function()
        vim.lsp.buf.format({ async = false })
      end,
    })
  end,
})

-- Tell Neovim about the AppArmor filetype
vim.filetype.add({
  pattern = {
    ['/etc/apparmor.d/.*']     = 'apparmor',
    ['/etc/apparmor/.*%.conf'] = 'apparmor',
    ['.*%.apparmor']           = 'apparmor',
  },
})
```

### VS Code

VS Code does not have a built-in generic LSP client. To use
`apparmor-language-server` you will need to write a small VS Code
extension that wraps it using the
[`vscode-languageclient`](https://www.npmjs.com/package/vscode-languageclient)
npm package, following the
[VS Code Language Server extension guide](https://code.visualstudio.com/api/language-extensions/language-server-extension-guide).

### Emacs (with `eglot`)

```elisp
(add-to-list 'auto-mode-alist '("/etc/apparmor\\.d/.*" . apparmor-mode))
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
               '(apparmor-mode . ("apparmor-language-server"))))
```

### Emacs (with `lsp-mode`)

```elisp
(with-eval-after-load 'lsp-mode
  (lsp-register-client
   (make-lsp-client
    :new-connection (lsp-stdio-connection '("apparmor-language-server"))
    :major-modes '(apparmor-mode)
    :server-id 'apparmor-language-server)))
```

### Helix

In `~/.config/helix/languages.toml`:

```toml
[[language]]
name              = "apparmor"
scope             = "source.apparmor"
file-types        = ["apparmor", { glob = "/etc/apparmor.d/**" }]
language-servers  = ["apparmor-language-server"]
comment-token     = "#"
indent            = { tab-width = 2, unit = "  " }

[language-server.apparmor-language-server]
command = "apparmor-language-server"
```

### Sublime Text (with `LSP` package)

In `LSP.sublime-settings`:

```json
{
  "clients": {
    "apparmor-language-server": {
      "enabled": true,
      "command": ["apparmor-language-server"],
      "selector": "source.apparmor"
    }
  }
}
```

---

## Formatting options

The formatter respects the editor's `tabSize` setting (passed via the LSP
`DocumentFormattingParams`). You can also influence formatting by editing
`apparmor_language_server/formatting.py`:

| Option | Default | Effect |
|---|---|---|
| `indent` | `"  "` (2 spaces) | Indentation string |
| `sort_capabilities` | `True` | Sort cap names alphabetically |
| `ensure_trailing_comma` | `True` | Add `,` to rule lines missing one |
| `normalize_include` | `True` | Rewrite `#include` as `include` |
| `max_blank_lines` | `1` | Collapse runs of blank lines |

---

## Diagnostics reference

| Code | Severity | Meaning |
|---|---|---|
| `parse-error` | Error | Syntax error detected by parser |
| `unknown-capability` | Error | Capability not in `man 7 capabilities` list |
| `unknown-flag` | Error | Unrecognised profile flag in `flags=(…)` |
| `unknown-network-qualifier` | Warning | Unknown network family or socket type |
| `unknown-keyword` | Warning | Unrecognised rule keyword |
| `dangerous-exec` | Warning | `ux`/`Ux`/`pux`/`PUx`/`cux`/`CUx` allows unconfined exec |
| `prefer-append` | Information | `w` on a log file; consider `a` instead |
| `empty-profile` | Warning | Profile body has no rules |
| `duplicate-capability` | Warning | Capability declared more than once |
| `conflicting-capability` | Warning | Same capability both allowed and denied |
| `undefined-variable` | Warning | `@{VAR}` used but never defined |
| `undefined-bool-variable` | Warning | `${BOOL_VAR}` referenced in an `if` condition but never defined |
| `missing-include` | Warning | Include target not found on disk |
| `missing-abi` | Warning | ABI target not found on disk |
| `unknown-signal-permission` | Warning | Invalid permission in `signal` rule |
| `unknown-signal-name` | Warning | Unknown signal name in `signal set=(…)` |
| `unknown-ptrace-permission` | Warning | Invalid permission in `ptrace` rule |
| `perm-conflict-write-append` | Error | `w` and `a` are mutually exclusive in a file rule |
| `multiple-exec-modes` | Error | More than one exec transition mode (e.g. `ix`, `px`, `cx`) in a single file rule |
| `exec-target-without-transition` | Error | `-> profile` exec target specified without an exec transition mode |
| `deny-with-exec-transition` | Error | Exec transition mode (e.g. `ix`, `px`) used with the `deny` qualifier — use `deny x` instead |
| `bare-x-without-deny` | Error | Bare `x` permission used without the `deny` qualifier — use an exec transition mode (`ix`, `px`, `cx`, …) |
| `allow-deny-conflict` | Error | `allow` and `deny` qualifiers used together on the same rule |
| `conflicting-profile-modes` | Error | More than one profile mode flag (`enforce`/`complain`/`kill`/`default_allow`/`unconfined`/`prompt`) set together |
| `invalid-error-flag-value` | Warning | `flags=(error=…)` value is not a valid `E…` errno name |
| `alias-relative-path` | Warning | `alias` source/target is not an absolute path |
| `unknown-mount-option` | Warning | Mount option not in the documented `mount(8)` flag list |
| `unknown-rlimit-resource` | Error | Resource name not recognised by `setrlimit(2)` |
| `invalid-rlimit-value` | Warning | rlimit value/unit doesn't match the resource family (size, time, integer, nice range -20..19) |
| `unknown-dbus-permission` | Warning | Invalid permission in `dbus` rule |
| `dbus-bind-in-message-rule` | Error | `bind` permission used in a dbus message rule (path/interface/member/peer) |
| `dbus-send-recv-in-service-rule` | Error | `send`/`receive` used in a dbus service rule (`name=`) |
| `dbus-eavesdrop-with-conds` | Error | `eavesdrop` used with conditionals other than `bus=` |
| `unknown-unix-permission` | Warning | Invalid permission in `unix` socket rule |
| `unknown-unix-type` | Warning | `type=` not in `stream`/`dgram`/`seqpacket` |
| `unknown-mqueue-permission` | Warning | Invalid permission in `mqueue` rule |
| `unknown-mqueue-type` | Warning | `type=` not in `posix`/`sysv` |
| `mqueue-posix-name-shape` | Error | POSIX mqueue name must start with `/` |
| `mqueue-sysv-name-shape` | Error | SysV mqueue name must be a positive integer |
| `unknown-io-uring-permission` | Warning | `io_uring` permission not in `sqpoll`/`override_creds`/`cmd` |
| `unknown-userns-permission` | Warning | `userns` permission other than `create` |
| `netlink-type-restricted` | Error | `network netlink` may only specify type `dgram` or `raw` |
| `pivot-root-trailing-slash` | Warning | `pivot_root` path doesn't end with `/` (paths refer to directories) |
| `apparmor-parser-error` | Error | Error reported by `apparmor_parser -Q -K`; attached to the file and line cited by the parser (may be an included abstraction) |

---

## Architecture

```
apparmor_language_server/
├── __init__.py         – package metadata
├── __main__.py         – python -m apparmor_language_server entry point
├── server.py           – pygls LSP server, all handler registration
├── indexer.py          – workspace indexer
├── parser.py           – line-oriented AST parser (profiles, rules, …)
├── constants.py        – capabilities, keywords, permissions, abstractions, …
├── completions.py      – context-aware completion provider
├── diagnostics.py      – linting / diagnostic checks
├── formatting.py       – auto-formatter (returns TextEdits)
├── hover.py            – hover documentation provider
├── lint.py             – standalone `apparmor-lint` CLI (parser + diagnostics, GCC/JSON output)
└── docs.py             – helpers for consistent hover/completion docs
```

### Adding new checks

Create a new `_check_*` function in `diagnostics.py` and call it from
`_check_node()`. Each check receives the AST node and appends `Diagnostic`
objects to the list.

### Adding new completions

Add entries to the relevant `_complete_*` function in `completions.py`, or
extend the `get_completions()` dispatcher with a new regex trigger.

---

## Development

```bash
# Install dev dependencies (includes pytest, ruff, ty, etc.)
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage, outputting both terminal and JSON reports
pytest --cov=apparmor_language_server --cov-report=term --cov-report=json

# Lint and format
ruff check apparmor_language_server/
ruff format apparmor_language_server/

# Type-check
ty check apparmor_language_server/

# Run the server in TCP mode for interactive debugging
python -m apparmor_language_server --tcp --port 2087
```

---

## Licence

GPL 3.0 or later
