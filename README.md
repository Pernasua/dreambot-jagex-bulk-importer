# DreamBot Jagex Bulk Importer

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

## CLI

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar \
  --input accounts.txt \
  --db /path/to/DreamBot/BotData/accounts.db
```

Input format:

```text
email:password:totp-secret
```

Passwords may contain `:`. The parser uses the first and last separators.

## GUI

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar
```

The GUI has start, pause/resume, and stop controls.
When a run finishes, the GUI opens the ledger file.

## Notes

- Does not require DreamBot.
- Does not bundle Chromium/JCEF browser binaries.
- Downloads the JCEF runtime on first embedded-browser use, then reuses the cache.
- Default JCEF cache:
  - Windows: `%LOCALAPPDATA%\DreamBotJagexBulkImporter\jcef`
  - Linux/macOS: `$XDG_CACHE_HOME/dreambot-jagex-bulk-importer/jcef` or `~/.cache/dreambot-jagex-bulk-importer/jcef`
- Linux embedded JCEF needs a display server. Use a desktop session or `xvfb-run`.
- `--system-browser` can use installed Chrome, Chromium, or Edge instead.
- The ledger is a JSONL audit file for row results. DreamBot does not read it.
- The ledger includes full emails, but not passwords, TOTP secrets, OTP values, or OAuth tokens.
- Wrong passwords and rejected authenticator codes are skipped with explicit ledger
  statuses: `invalid_credentials`, `invalid_otp_code`, or `account_locked`.

## Useful Commands

```bash
java -jar dist/dreambot-jagex-bulk-importer.jar --db-info /path/to/accounts.db
java -jar dist/dreambot-jagex-bulk-importer.jar --browser-check
java -jar dist/dreambot-jagex-bulk-importer.jar --totp BASE32SECRET
```
