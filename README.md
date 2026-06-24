# Pernasua DreamBot Jagex Bulk Importer

Standalone Java importer for adding legacy and Jagex accounts to a DreamBot
`BotData/accounts.db`.

## Build

```bash
./build.sh
```

Output:

```text
dist/dreambot-jagex-bulk-importer.jar
```

## Import Accounts

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar \
  --input accounts.txt \
  --db /path/to/DreamBot/BotData/accounts.db
```

If `--db` is omitted, the importer makes one attempt to auto-detect a common
DreamBot `BotData/accounts.db` path.

Input rows use:

```text
email:password:totp-secret
```

Passwords may contain `:`. The parser uses the first separator for the email
and the last separator for the TOTP secret.

## CLI Reference

### Main Modes

| Mode | Description |
| --- | --- |
| `--gui` | Open the Swing GUI. Running the jar with no arguments does the same thing. |
| `--help`, `-h` | Print usage. |
| `--input PATH [--db PATH]` | Import rows from a file into `accounts.db`. |
| `--stdin [--db PATH]` | Import rows from standard input. |
| `--db-info PATH` | Print JSON with account count, account-store codec label, and AAD. |
| `--db-browser PATH` | Open a full table view of `accounts.db`. |
| `--browser-check` | Launch the configured browser and report DevTools status. |
| `--page-state --devtools-port N` | Print JSON describing the current browser page. |
| `--totp SECRET` | Print the current TOTP code for a base32 secret. |
| `--enroll-only` | Enroll authenticator secrets and print `email:password:secret` rows. |
| `--disable-email-only` | Disable email MFA for one account. |

### Import Flags

These flags apply to `--input ...` and `--stdin` import runs.

| Flag | Description |
| --- | --- |
| `--input PATH` | Account list file. Required unless `--stdin` is used. |
| `--stdin` | Read account rows from standard input. |
| `--db PATH` | DreamBot `BotData/accounts.db` to update. Auto-detected if omitted. |
| `--start N` | First 1-based source row to import. Default: `1`. |
| `--end N` | Last 1-based source row to import. Default: last row. |
| `--ledger PATH` | Non-secret JSONL result ledger. Default: next to `accounts.db`. |
| `--browser-engine jcef\|system` | Browser engine. Default: `jcef`. |
| `--browser PATH` | Chrome, Chromium, or Edge executable for `system` browser mode. |
| `--user-data-dir PATH` | Reuse a system browser profile directory. |
| `--jcef-dir PATH` | Embedded JCEF runtime cache directory. |
| `--headless` | Run the selected browser headless/minimized. |
| `--headed` | Show the selected browser window. |
| `--devtools-port N` | Browser DevTools port. Default: auto. |
| `--human-check-wait-ms N` | Max wait for Jagex/Cloudflare human checks. Default: `300000`. |
| `--keep-browser-open` | Leave the browser open after import attempts. |
| `--allow-dreambot-running` | Bypass the DreamBot process guard for isolated DB copies. |
| `--dry-run` | Parse rows, validate TOTP secrets, and decrypt DB without importing. |
| `--mail-code-helper PATH` | Helper command used when login needs an email verification code. |

### Browser Check Flags

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar --browser-check [flags]
```

| Flag | Description |
| --- | --- |
| `--browser-engine jcef\|system` | Browser engine. Default: `jcef`, or `system` when `--browser` is set. |
| `--browser PATH` | Chrome, Chromium, or Edge executable. |
| `--jcef-dir PATH` | Embedded JCEF runtime cache directory. |
| `--devtools-port N` | Browser DevTools port. Default: auto. |
| `--headless` | Force headless/minimized browser mode. |
| `--headed` | Force visible browser mode. |

### Page State Flags

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar --page-state --devtools-port N
```

| Flag | Description |
| --- | --- |
| `--devtools-port N` | Existing browser DevTools port. Required. |

### Enroll-Only Flags

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar --enroll-only --input accounts.txt
java -jar dist/dreambot-jagex-bulk-importer.jar --enroll-only --account email:password
```

| Flag | Description |
| --- | --- |
| `--input PATH` | File containing `email:password` rows. Required unless `--account` is used. |
| `--account email:password` | Single account to enroll. |
| `--browser-engine jcef\|system` | Browser engine. Default: `jcef`. |
| `--browser PATH` | Chrome, Chromium, or Edge executable for `system` browser mode. |
| `--user-data-dir PATH` | Reuse a system browser profile directory. |
| `--jcef-dir PATH` | Embedded JCEF runtime cache directory. |
| `--devtools-port N` | Browser DevTools port. Default: auto. |
| `--human-check-wait-ms N` | Max wait for Jagex/Cloudflare human checks. Default: `300000`. |
| `--headless` | Force headless/minimized browser mode. |
| `--headed` | Force visible browser mode. |
| `--ledger PATH` | Optional non-secret JSONL enrollment ledger. |
| `--mail-code-helper PATH` | Helper command used to read email verification codes. |

### Disable-Email-Only Flags

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar \
  --disable-email-only \
  --account email:password:secret
```

| Flag | Description |
| --- | --- |
| `--account email:password:secret` | Account and authenticator secret. Required. |
| `--browser-engine jcef\|system` | Browser engine. Default: `jcef`. |
| `--browser PATH` | Chrome, Chromium, or Edge executable for `system` browser mode. |
| `--user-data-dir PATH` | Reuse a system browser profile directory. |
| `--jcef-dir PATH` | Embedded JCEF runtime cache directory. |
| `--devtools-port N` | Browser DevTools port. Default: auto. |
| `--human-check-wait-ms N` | Max wait for Jagex/Cloudflare human checks. Default: `300000`. |
| `--headless` | Force headless/minimized browser mode. |
| `--headed` | Force visible browser mode. |
| `--mail-code-helper PATH` | Helper command used to read email verification codes. |

## GUI

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar
```

The GUI has start, pause/resume, and stop controls. It makes one startup attempt
to auto-detect the `accounts.db` path. Selecting an `accounts.db` file does not
parse or decrypt it. `View DB` opens a full table view of the account rows.
When a run finishes, the GUI opens the ledger file.

## Behavior Notes

- Does not require DreamBot.
- Automatically discovers the DreamBot account-store AAD value. This keeps the
  importer standalone while tolerating DreamBot updates that change the AES-GCM
  associated-data value without rotating the account-store key.
- Close DreamBot before importing. The importer refuses to write while a DreamBot
  process appears to be running or another process has `accounts.db` open,
  because DreamBot can overwrite `accounts.db` with an older in-memory account
  list.
- Does not bundle Chromium/JCEF browser binaries.
- Downloads the JCEF runtime on first embedded browser use, then reuses the cache.
- Default JCEF cache:
  - Windows: `%LOCALAPPDATA%\DreamBotJagexBulkImporter\jcef`
  - Linux/macOS: `$XDG_CACHE_HOME/dreambot-jagex-bulk-importer/jcef` or
    `~/.cache/dreambot-jagex-bulk-importer/jcef`
- Linux embedded JCEF needs a display server. Use a desktop session or `xvfb-run`.
- `--browser-engine system` uses installed Chrome, Chromium, or Edge.
- The ledger is a JSONL audit file for row results. DreamBot does not read it.
- The ledger does not include account identifiers, passwords, TOTP secrets, OTP
  values, or OAuth tokens. Use row indexes to map results back to the input file.
- Each successful write is reopened and verified against the encrypted
  `accounts.db`.
- Wrong passwords and rejected authenticator codes are skipped with explicit ledger
  statuses: `invalid_credentials`, `invalid_otp_code`, or `account_locked`.
- Human-check handling logs detection reason, click attempts, screenshot paths,
  and timeout details so Cloudflare/Jagex challenge failures are diagnosable.

If `--db-info` reports that no scanned AAD value can decrypt the file, close
DreamBot and copy `BotData/accounts.db` again. If DreamBot can still read the
same file, DreamBot likely rotated the account-store key rather than only the
AAD; that cannot be recovered from the hex prefix alone.
