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
| **Diagnostics / Linting** | Unknown capabilities, invalid network qualifiers, bad file permission chars, dangerous unconfined exec (`ux`/`Ux`), empty profiles, duplicate capabilities, conflicting allow+deny, undefined variables, missing include targets, unclosed profiles, unknown profile flags |
| **Formatting** | Normalise indentation, remove trailing whitespace, sort capabilities alphabetically, sort parenthesised lists, ensure trailing commas on all rules, normalise `#include` → `include`, collapse multiple blank lines |
| **Range Formatting** | Format a selected region only |
| **Document Highlight** | Highlight all occurrences of the word under the cursor |

---

## Installation

### Prerequisites

- Python ≥ 3.10
- `pip`

### From source

```bash
git clone https://github.com/example/apparmor-language-server
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

Install the [generic LSP client](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd)
or create a `.vscode/settings.json`:

```json
{
  "languageserver": {
    "apparmor": {
      "command": "apparmor-language-server",
      "args": [],
      "filetypes": ["apparmor"]
    }
  }
}
```

If using the **`vscode-glspc`** or **`georgewfraser.vscode-langserver-node`** extension:

```json
{
  "glspc.serverPath": "apparmor-language-server",
  "glspc.languageId": "apparmor"
}
```

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
| `dangerous-exec` | Warning | `ux`/`Ux`/`pux`/`cux` allows unconfined exec |
| `prefer-append` | Information | `w` on a log file; consider `a` instead |
| `empty-profile` | Warning | Profile body has no rules |
| `duplicate-capability` | Warning | Capability declared more than once |
| `conflicting-capability` | Warning | Same capability both allowed and denied |
| `undefined-variable` | Warning | `@{VAR}` used but never defined |
| `missing-include` | Warning | Include target not found on disk |
| `missing-abi` | Warning | ABI target not found on disk |
| `unknown-signal-permission` | Warning | Invalid permission in `signal` rule |
| `unknown-signal-name` | Warning | Unknown signal name in `signal set=(…)` |

---

## Architecture

```
apparmor_language_server/
├── __init__.py         – package metadata
├── __main__.py         – python -m apparmor_language_server entry point
├── server.py           – pygls LSP server, all handler registration
├── parser.py           – line-oriented AST parser (profiles, rules, …)
├── constants.py        – capabilities, keywords, permissions, abstractions, …
├── completions.py      – context-aware completion provider
├── diagnostics.py      – linting / diagnostic checks
├── formatting.py       – auto-formatter (returns TextEdits)
└── hover.py            – hover documentation provider
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
