package com.pernasua.dreambot.jageximporter;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

public final class DreamBotJagexBulkImporter {
  private static final long DEFAULT_HUMAN_CHECK_WAIT_MS = 300_000L;
  private static final int MAX_TEMPORARY_OAUTH_ATTEMPTS =
      positiveEnvInt("DREAMBOT_JAGEX_IMPORTER_TEMP_OAUTH_ATTEMPTS", 4);
  private static final Progress NO_PROGRESS = new Progress() { };
  private static final DateTimeFormatter FILE_STAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

  private DreamBotJagexBulkImporter() {
  }

  private static int positiveEnvInt(String name, int fallback) {
    String raw = String.valueOf(System.getenv(name) == null ? "" : System.getenv(name)).trim();
    if (raw.isEmpty()) {
      return fallback;
    }
    try {
      return Math.max(1, Integer.parseInt(raw));
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }

  public static void main(String[] args) {
    try {
      int exit = runMain(args);
      if (exit != 0) {
        System.exit(exit);
      }
    } catch (Throwable throwable) {
      System.err.println(throwable.getMessage() == null ? throwable.toString() : throwable.getMessage());
      System.exit(1);
    }
  }

  private static int runMain(String[] args) throws Exception {
    List<String> argv = new ArrayList<>(Arrays.asList(args));
    if (argv.isEmpty() || argv.contains("--gui")) {
      SwingUtilities.invokeLater(() -> new Gui().show());
      return 0;
    }
    if (argv.contains("--help") || argv.contains("-h")) {
      printUsage();
      return 0;
    }
    if ("--totp".equals(argv.get(0))) {
      if (argv.size() < 2) {
        throw new IllegalArgumentException("--totp requires a base32 secret");
      }
      Totp.Code code = generateFreshTotp(argv.get(1));
      LinkedHashMap<String, Object> out = new LinkedHashMap<>();
      out.put("code", code.value);
      out.put("remaining_seconds", code.remainingSeconds);
      out.put("period", code.period);
      System.out.println(Json.stringify(out));
      return 0;
    }
    if ("--db-info".equals(argv.get(0))) {
      Path db = Paths.get(requireValue(argv, 1, "--db-info"));
      DreamBotAccountStore.Info info = DreamBotAccountStore.info(db);
      LinkedHashMap<String, Object> out = new LinkedHashMap<>();
      out.put("ok", true);
      out.put("accounts", info.count);
      System.out.println(Json.stringify(out));
      return 0;
    }
    if ("--browser-check".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()));
      String browser = options.getOrDefault("browser", "");
      BrowserEngine engine = browser.isEmpty()
          ? BrowserEngine.parse(options.getOrDefault("browser-engine", "jcef"))
          : BrowserEngine.parse(options.getOrDefault("browser-engine", "system"));
      if (options.containsKey("system-browser")) {
        engine = BrowserEngine.SYSTEM;
      } else if (options.containsKey("embedded-browser")) {
        engine = BrowserEngine.JCEF;
      }
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      Boolean headless = null;
      if (options.containsKey("headless")) {
        headless = isTruthy(options.get("headless"));
      } else if (options.containsKey("headed")) {
        headless = !isTruthy(options.get("headed"));
      }
      boolean effectiveHeadless = headless == null ? engine == BrowserEngine.JCEF : headless;
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      try (BrowserSession session = launchBrowser(engine, browser, jcefDir, port, false, effectiveHeadless,
          null,
          message -> System.err.println(message))) {
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("engine", session.engine.label);
        out.put("headless", session.headless);
        out.put("port", session.port);
        out.put("targets", CdpClient.targets(session.endpoint).size());
        System.out.println(Json.stringify(out));
      }
      return 0;
    }
    if ("--page-state".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()));
      int port = Integer.parseInt(options.getOrDefault("devtools-port", "0"));
      if (port <= 0) {
        throw new IllegalArgumentException("--page-state requires --devtools-port");
      }
      try (CdpClient cdp = CdpClient.connect(CdpClient.pageWebSocket("http://127.0.0.1:" + port))) {
        cdp.send("Runtime.enable");
        Object value = cdp.evaluate(pageStateScript());
        System.out.println(Json.stringify(value));
      }
      return 0;
    }
    if ("--enroll-only".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()));
      List<String> rows = new ArrayList<>();
      if (options.containsKey("input")) {
        for (String line : Files.readAllLines(Paths.get(options.get("input")), StandardCharsets.UTF_8)) {
          String trimmed = line.trim();
          if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
            rows.add(trimmed);
          }
        }
      }
      if (options.containsKey("account")) {
        rows.add(options.get("account"));
      }
      if (rows.isEmpty()) {
        throw new IllegalArgumentException("--enroll-only requires --input PATH or --account email:password");
      }
      BrowserEngine engine = BrowserEngine.parse(options.getOrDefault("browser-engine", "jcef"));
      if (options.containsKey("system-browser")) {
        engine = BrowserEngine.SYSTEM;
      } else if (options.containsKey("embedded-browser")) {
        engine = BrowserEngine.JCEF;
      }
      String browserPath = options.getOrDefault("browser", "");
      Path userDataDir = options.containsKey("user-data-dir") ? Paths.get(options.get("user-data-dir")) : null;
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      long humanWait = options.containsKey("human-check-wait-ms")
          ? Long.parseLong(options.get("human-check-wait-ms")) : 300_000L;
      boolean headless = engine == BrowserEngine.JCEF;
      if (options.containsKey("headed")) {
        headless = !isTruthy(options.get("headed"));
      } else if (options.containsKey("headless")) {
        headless = isTruthy(options.get("headless"));
      }
      Path ledger = options.containsKey("ledger") ? Paths.get(options.get("ledger")) : null;
      Path bandwidthOut = ledger == null ? null : defaultBandwidth(ledger);
      String mailCodeHelper = options.getOrDefault("mail-code-helper",
          "/root/projects/dreambot/tools/2b2m_mail_code.py");
      int ok = 0;
      BandwidthAudit.reset();
      try {
        for (int rowIndex = 0; rowIndex < rows.size(); rowIndex++) {
          String row = rows.get(rowIndex);
          int displayIndex = rowIndex + 1;
          String[] parts = row.split(":", -1);
          String email = parts[0].trim();
          String password = parts.length > 1 ? parts[1] : "";
          if (email.isEmpty() || password.isEmpty()) {
            System.err.println("skip malformed row " + displayIndex);
            continue;
          }
          try (BrowserSession browser = launchBrowser(engine, browserPath, jcefDir, port, false, headless,
              userDataDir,
              message -> System.err.println("row " + displayIndex + " " + message))) {
            JagexCdpAutomation automation = new JagexCdpAutomation(browser, humanWait,
                message -> System.err.println("row " + displayIndex + " " + message));
            String secret = automation.enrollAuthenticator(email, password, mailCodeHelper);
            ok++;
            System.out.println(email + ":" + password + ":" + secret);
            if (ledger != null) {
              LinkedHashMap<String, Object> entry = new LinkedHashMap<>();
              entry.put("index", displayIndex);
              entry.put("status", "enrolled");
              Files.writeString(ledger, Json.stringify(entry) + "\n", StandardCharsets.UTF_8,
                  java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            }
          } catch (Exception exception) {
            String message = redactValues(exception.getMessage() == null ? exception.toString() : exception.getMessage(),
                email, password);
            System.err.println("row " + displayIndex + " enrollment failed: " + message);
            if (ledger != null) {
              LinkedHashMap<String, Object> entry = new LinkedHashMap<>();
              entry.put("index", displayIndex);
              entry.put("status", "enroll_failed");
              entry.put("error", message);
              Files.writeString(ledger, Json.stringify(entry) + "\n", StandardCharsets.UTF_8,
                  java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            }
          }
        }
      } finally {
        if (bandwidthOut != null) {
          BandwidthAudit.write(bandwidthOut);
          chmod600(bandwidthOut);
        }
      }
      return ok == rows.size() ? 0 : 1;
    }
    if ("--disable-email-only".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()));
      String account = options.get("account");
      if (account == null || account.isEmpty()) {
        throw new IllegalArgumentException("--disable-email-only requires --account email:password:secret");
      }
      String[] parts = account.split(":", -1);
      String email = parts[0].trim();
      String password = parts.length > 1 ? parts[1] : "";
      String secret = parts.length > 2 ? parts[2].trim() : "";
      if (email.isEmpty() || password.isEmpty() || secret.isEmpty()) {
        throw new IllegalArgumentException("--account must be email:password:secret");
      }
      BrowserEngine engine = BrowserEngine.parse(options.getOrDefault("browser-engine", "jcef"));
      if (options.containsKey("system-browser")) {
        engine = BrowserEngine.SYSTEM;
      } else if (options.containsKey("embedded-browser")) {
        engine = BrowserEngine.JCEF;
      }
      String browserPath = options.getOrDefault("browser", "");
      Path userDataDir = options.containsKey("user-data-dir") ? Paths.get(options.get("user-data-dir")) : null;
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      long humanWait = options.containsKey("human-check-wait-ms")
          ? Long.parseLong(options.get("human-check-wait-ms")) : 300_000L;
      boolean headless = engine == BrowserEngine.JCEF;
      if (options.containsKey("headed")) {
        headless = !isTruthy(options.get("headed"));
      } else if (options.containsKey("headless")) {
        headless = isTruthy(options.get("headless"));
      }
      String mailCodeHelper = options.getOrDefault("mail-code-helper",
          "/root/projects/dreambot/tools/2b2m_mail_code.py");
      try (BrowserSession browser = launchBrowser(engine, browserPath, jcefDir, port, false, headless,
          userDataDir,
          message -> System.err.println("disable-email " + message))) {
        JagexCdpAutomation automation = new JagexCdpAutomation(browser, humanWait,
            message -> System.err.println("disable-email " + message));
        String result = automation.disableEmailOnly(email, password, secret, mailCodeHelper);
        System.out.println(result);
        return 0;
      } catch (Exception exception) {
        String message = redactValues(exception.getMessage() == null ? exception.toString() : exception.getMessage(),
            email, password, secret);
        System.err.println("disable-email failed: " + message);
        return 1;
      }
    }
    Config config = Config.parse(argv);
    return new Importer(config, System.out::println).run();
  }

  private static Totp.Code generateFreshTotp(String secret) throws InterruptedException {
    Totp.Code code = Totp.generate(secret);
    if (code.remainingSeconds < 8) {
      Thread.sleep((code.remainingSeconds + 2L) * 1000L);
      code = Totp.generate(secret);
    }
    return code;
  }

  private static void printUsage() {
    System.out.println(String.join("\n",
        "Usage:",
        "  java -jar dreambot-jagex-bulk-importer.jar --input accounts.txt --db accounts.db [options]",
        "  java -jar dreambot-jagex-bulk-importer.jar --stdin --db accounts.db [options]",
        "  java -jar dreambot-jagex-bulk-importer.jar --gui",
        "  java -jar dreambot-jagex-bulk-importer.jar --db-info accounts.db",
        "  java -jar dreambot-jagex-bulk-importer.jar --browser-check [--browser-engine jcef|system]",
        "  java -jar dreambot-jagex-bulk-importer.jar --page-state --devtools-port N",
        "",
        "Input rows use: username:password:otp-secret",
        "",
        "Options:",
        "  --input PATH              Account list file",
        "  --stdin                   Read account rows from stdin",
        "  --db PATH                 DreamBot BotData/accounts.db to update",
        "  --start N                 First 1-based source row to import (default: 1)",
        "  --end N                   Last 1-based source row to import (default: last row)",
        "  --ledger PATH             Non-secret JSONL result ledger",
        "  --browser-engine NAME     jcef/default embedded browser, or system Chrome/Edge",
        "  --embedded-browser        Use the embedded JCEF browser (default)",
        "  --system-browser          Use installed Chrome, Chromium, or Edge",
        "  --browser PATH            System Chrome, Chromium, or Edge executable",
        "  --user-data-dir PATH      Reuse a system-browser profile directory",
        "  --jcef-dir PATH           Embedded JCEF native-runtime cache directory",
        "  --headless                Run system browser headless; embedded JCEF starts minimized/internal",
        "  --headed                  Show the selected browser window",
        "  --devtools-port N         Browser DevTools port (default: auto)",
        "  --human-check-wait-ms N   Max wait for browser challenge pages (default: 300000)",
        "  --keep-browser-open       Leave browser open after import attempts",
        "  --allow-dreambot-running Bypass the DreamBot process guard for isolated DB copies",
        "  --dry-run                 Parse rows, validate TOTP, and decrypt DB without importing",
        "  --totp SECRET             Utility mode: print the current generated TOTP code"));
  }

  private interface Progress {
    default void total(int total) {
    }

    default void row(int completed, int total, String message) {
    }
  }

  private static BrowserSession launchBrowser(BrowserEngine engine, String browserPath, Path jcefDir,
      int devtoolsPort, boolean keepBrowserOpen, boolean headless, Path userDataDir,
      Consumer<String> log) throws Exception {
    if (engine == BrowserEngine.JCEF) {
      return JcefBrowserLauncher.launch(jcefDir, devtoolsPort, keepBrowserOpen, headless, log);
    }
    return BrowserLauncher.launch(browserPath, devtoolsPort, keepBrowserOpen, headless, userDataDir);
  }

  private static final class Importer {
    private final Config config;
    private final Consumer<String> log;
    private final Progress progress;
    private final RunControl control;
    private final DreamBotAccountStore.BackupContext backupContext = DreamBotAccountStore.backupContext();
    private int expectedDbCount = -1;

    Importer(Config config, Consumer<String> log) {
      this(config, log, NO_PROGRESS);
    }

    Importer(Config config, Consumer<String> log, Progress progress) {
      this(config, log, progress, RunControl.NONE);
    }

    Importer(Config config, Consumer<String> log, Progress progress, RunControl control) {
      this.config = config;
      this.log = log == null ? ignored -> { } : log;
      this.progress = progress == null ? NO_PROGRESS : progress;
      this.control = control == null ? RunControl.NONE : control;
    }

    int run() throws Exception {
      List<AccountRow> rows = config.stdin ? readRowsFromStdin() : readRows(config.input);
      if (rows.isEmpty()) {
        throw new IllegalArgumentException("no account rows were found");
      }
      if (config.db == null) {
        throw new IllegalArgumentException("--db is required");
      }
      int end = config.end <= 0 ? rows.size() : Math.min(config.end, rows.size());
      if (config.start < 1 || config.start > end) {
        throw new IllegalArgumentException("invalid row range: " + config.start + " to " + end);
      }
      try {
        if (config.ledger == null) {
          config.ledger = defaultLedger(config.db);
        }
        if (config.bandwidthOut == null) {
          config.bandwidthOut = defaultBandwidth(config.ledger);
        }
        Files.createDirectories(config.ledger.toAbsolutePath().getParent());
        BandwidthAudit.reset();
        if (!config.dryRun) {
          guardDreamBotNotRunning(config, log);
          guardAccountsDbNotOpen(config.db);
        }
        warnIfDbPathLooksUnexpected(config.db, log);

        DreamBotAccountStore.Info info = DreamBotAccountStore.info(config.db);
        expectedDbCount = info.count;
        log.accept("DB opened: " + info.count + " accounts");
        log.accept("Loaded " + rows.size() + " account row(s); importing rows " + config.start + "-" + end);
        log.accept("Ledger: " + config.ledger + " (JSONL row-status audit; not used as the account database)");
        log.accept("Bandwidth: " + config.bandwidthOut + " (JSON summary for browser/API traffic)");
        if (!config.dryRun) {
          log.accept(browserSummary(config));
        }

        int failures = 0;
        JagexOAuthClient oauth = new JagexOAuthClient(message -> log.accept(message));
        int total = end - config.start + 1;
        progress.total(total);
        for (int rowIndex = config.start; rowIndex <= end; rowIndex++) {
          control.checkpoint();
          AccountRow account = rows.get(rowIndex - 1).withIndex(rowIndex);
          int completedBefore = rowIndex - config.start;
          progress.row(completedBefore, total, "Starting row " + account.index);
          try {
            String status = importOne(oauth, account);
            progress.row(completedBefore + 1, total, "Row " + account.index + " " + status);
          } catch (CancellationException exception) {
            throw exception;
          } catch (JagexCdpAutomation.TerminalAuthException exception) {
            String detail = redact(account, exception.getMessage() == null ? exception.toString() : exception.getMessage());
            log.accept("row " + account.index + " skipped: " + detail);
            record(account, exception.status(), detail, 0, null);
            progress.row(completedBefore + 1, total, "Row " + account.index + " " + exception.status());
          } catch (Exception exception) {
            failures++;
            String detail = redact(account, exception.getMessage() == null ? exception.toString() : exception.getMessage());
            String exceptionType = exception.getClass().getName();
            java.io.StringWriter stackBuffer = new java.io.StringWriter();
            exception.printStackTrace(new java.io.PrintWriter(stackBuffer));
            log.accept("row " + account.index + " failed: " + detail);
            log.accept("row " + account.index + " failed type: " + exceptionType);
            log.accept("row " + account.index + " failed stack: " + truncate(redact(account, stackBuffer.toString()), 4000));
            record(account, "failed", detail, 0, null);
            progress.row(completedBefore + 1, total, "Row " + account.index + " failed");
          }
        }
        DreamBotAccountStore.Info finalInfo = verifyFinalDbCount();
        recordRun(failures == 0 ? "finished" : "finished_with_failures",
            "Final DB verified with " + finalInfo.count + " account(s)", finalInfo.count);
        log.accept("Final DB verified: " + finalInfo.count + " accounts");
        return failures == 0 ? 0 : 1;
      } finally {
        if (config.bandwidthOut != null) {
          BandwidthAudit.write(config.bandwidthOut);
          chmod600(config.bandwidthOut);
        }
      }
    }

    private String importOne(JagexOAuthClient oauth, AccountRow account) throws Exception {
      control.checkpoint();
      account.validate();
      log.accept("row " + account.index + " start");
      log.accept("row " + account.index + " input validated; OTP secret accepted");
      if (config.dryRun) {
        Totp.Code code = Totp.generate(account.otpSecret);
        record(account, "dry_run_ok", "validated row, generated TOTP, and decrypted DB", 0, null);
        log.accept("row " + account.index + " generated TOTP code; value hidden, period "
            + code.period + "s, " + code.remainingSeconds + "s remaining, counter " + code.counter);
        log.accept("row " + account.index + " dry-run ok");
        return "dry_run_ok";
      }

      for (int attempt = 1; attempt <= MAX_TEMPORARY_OAUTH_ATTEMPTS; attempt++) {
        control.checkpoint();
        try (BrowserSession browser = launchBrowser(config.browserEngine, config.browserPath, config.jcefDir,
            config.devtoolsPort, config.keepBrowserOpen, config.isHeadless(), config.userDataDir,
              message -> log.accept("row " + account.index + " " + message))) {
          JagexCdpAutomation automation = new JagexCdpAutomation(browser, config.humanCheckWaitMs,
              message -> log.accept("row " + account.index + " " + message), control);
          automation.setImportMailCodeHelper(config.mailCodeHelper);

          log.accept("row " + account.index + " launcher OAuth attempt " + attempt
              + "/" + MAX_TEMPORARY_OAUTH_ATTEMPTS + " starting");
          JagexOAuthClient.AuthRequest launcherRequest = oauth.launcherAuthRequest();
          JagexOAuthClient.Callback launcherCallback =
              automation.completeAuth(launcherRequest, account.email, account.password, account.otpSecret);
          if (launcherCallback.code.isEmpty()) {
            throw new IllegalStateException("launcher OAuth callback did not contain an authorization code");
          }
          log.accept("row " + account.index + " launcher OAuth callback received; exchanging authorization code");

          JagexOAuthClient.Tokens tokens = oauth.exchangeLauncherCode(launcherRequest, launcherCallback.code);
          String provider = tokens.loginProvider.toLowerCase(Locale.ROOT);
          log.accept("row " + account.index + " launcher OAuth exchange complete; provider " + provider
              + ", token expiry " + Instant.ofEpochSecond(tokens.expiresAt));
          if ("runescape".equals(provider)) {
            control.checkpoint();
            log.accept("row " + account.index + " fetching legacy RuneScape profile");
            JagexOAuthClient.RunescapeProfile profile = oauth.fetchRunescapeProfile(tokens.idToken);
            guardAccountsDbNotOpen(config.db);
            DreamBotAccountStore.AddResult result =
                DreamBotAccountStore.addLegacyAccount(config.db, account, profile, backupContext);
            result = verifyStoreResult(result, "legacy account add");
            if (result.addedCount == 0) {
              log.accept("row " + account.index + " already present");
              record(account, "already_present", "", 0, null);
              return "already_present";
            }
            log.accept("row " + account.index + " added legacy account");
            String detail = profile.displayNameSet && !profile.displayName.isBlank()
                ? "verified legacy login; nickname " + profile.displayName
                : "verified legacy login";
            record(account, "added_legacy", detail, result.addedCount, result.backup);
            return "added_legacy";
          }

          control.checkpoint();
          log.accept("row " + account.index + " starting Jagex account consent OAuth");
          JagexOAuthClient.AuthRequest consentRequest = oauth.consentAuthRequest(tokens);
          JagexOAuthClient.Callback consentCallback =
              automation.completeAuth(consentRequest, account.email, account.password, account.otpSecret);
          if (consentCallback.idToken.isEmpty()) {
            throw new IllegalStateException("consent OAuth callback did not contain an id_token");
          }
          log.accept("row " + account.index + " consent OAuth callback received; fetching game session");

          control.checkpoint();
          JagexOAuthClient.GameSession session;
          try {
            session = oauth.fetchGameSession(consentCallback.idToken);
          } catch (java.io.IOException exception) {
            throw new JagexCdpAutomation.TemporaryOAuthException(
                "game-session transport failure after consent OAuth: "
                    + shortReason(exception.getMessage() == null ? exception.toString() : exception.getMessage()));
          }
          log.accept("row " + account.index + " game session fetched; " + session.accounts.size()
              + " character account(s)");
          guardAccountsDbNotOpen(config.db);
          DreamBotAccountStore.AddResult result =
              DreamBotAccountStore.addJagexAccount(config.db, account, tokens, session, backupContext);
          result = verifyStoreResult(result, "Jagex account add");
          if (result.addedCount == 0) {
            log.accept("row " + account.index + " already present");
            record(account, "already_present", "", 0, null);
            return "already_present";
          }
          log.accept("row " + account.index + " added " + result.addedCount + " character(s)");
          record(account, "added", "DB count " + result.beforeCount + " -> " + result.afterCount,
              result.addedCount, result.backup);
          return "added";
        } catch (JagexCdpAutomation.TemporaryOAuthException exception) {
          if (attempt >= MAX_TEMPORARY_OAUTH_ATTEMPTS) {
            throw exception;
          }
          log.accept("row " + account.index + " temporary Jagex OAuth page ("
              + shortReason(exception.getMessage()) + "); retrying with fresh browser "
              + (attempt + 1) + "/" + MAX_TEMPORARY_OAUTH_ATTEMPTS);
          sleepBeforeRetry(attempt);
        }
      }
      throw new IllegalStateException("temporary Jagex OAuth retry loop ended unexpectedly");
    }

    private DreamBotAccountStore.AddResult verifyStoreResult(DreamBotAccountStore.AddResult result,
        String action) throws Exception {
      if (expectedDbCount >= 0 && result.beforeCount != expectedDbCount) {
        throw new IllegalStateException("accounts.db changed outside the importer before " + action
            + ": expected " + expectedDbCount + " account(s), found " + result.beforeCount
            + ". Close DreamBot and rerun so it cannot overwrite the account store.");
      }
      DreamBotAccountStore.Info persisted = DreamBotAccountStore.info(config.db);
      if (persisted.count != result.afterCount) {
        throw new IllegalStateException("accounts.db verification failed after " + action
            + ": expected " + result.afterCount + " account(s), found " + persisted.count
            + ". Close DreamBot and rerun so it cannot overwrite the account store.");
      }
      expectedDbCount = persisted.count;
      return result;
    }

    private DreamBotAccountStore.Info verifyFinalDbCount() throws Exception {
      DreamBotAccountStore.Info persisted = DreamBotAccountStore.info(config.db);
      if (expectedDbCount >= 0 && persisted.count != expectedDbCount) {
        throw new IllegalStateException("accounts.db final verification failed: expected "
            + expectedDbCount + " account(s), found " + persisted.count
            + ". Close DreamBot and rerun so it cannot overwrite the account store.");
      }
      return persisted;
    }

    private String browserSummary(Config config) {
      String visibility = config.isHeadless() && config.browserEngine == BrowserEngine.JCEF
          ? "minimized/internal"
          : (config.isHeadless() ? "headless" : "visible");
      if (config.browserEngine == BrowserEngine.JCEF) {
        Path jcefDir = config.jcefDir == null ? JcefBrowserLauncher.defaultInstallDir() : config.jcefDir;
        return "Browser: embedded JCEF (" + visibility + "), runtime cache " + jcefDir.toAbsolutePath();
      }
      return "Browser: " + BrowserLauncher.locateBrowser(config.browserPath) + " (" + visibility + ")";
    }

    private void sleepBeforeRetry(int attempt) {
      control.sleep(Math.min(15_000L, 4_000L * attempt));
    }

    private String shortReason(String message) {
      String reason = message == null ? "" : message.replaceAll("\\s+", " ").trim();
      if (reason.length() > 220) {
        return reason.substring(0, 220) + "...";
      }
      return reason.isEmpty() ? "no detail" : reason;
    }

    private List<AccountRow> readRowsFromStdin() throws IOException {
      ArrayList<AccountRow> rows = new ArrayList<>();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
        String line;
        int sourceLine = 0;
        while ((line = reader.readLine()) != null) {
          sourceLine++;
          AccountRow parsed = AccountRow.parse(line, sourceLine);
          if (parsed != null) {
            rows.add(parsed);
          }
        }
      }
      return rows;
    }

    private List<AccountRow> readRows(Path input) throws IOException {
      if (input == null || !Files.isRegularFile(input)) {
        throw new IllegalArgumentException("input file does not exist: " + input);
      }
      ArrayList<AccountRow> rows = new ArrayList<>();
      int sourceLine = 0;
      for (String line : Files.readAllLines(input, StandardCharsets.UTF_8)) {
        sourceLine++;
        AccountRow parsed = AccountRow.parse(line, sourceLine);
        if (parsed != null) {
          rows.add(parsed);
        }
      }
      return rows;
    }

    private void record(AccountRow account, String status, String detail, int addedCount, Path backup) throws IOException {
      LinkedHashMap<String, Object> row = new LinkedHashMap<>();
      row.put("at", Instant.now().toString());
      row.put("index", account.index);
      row.put("source_line", account.sourceLine);
      row.put("status", status);
      if (addedCount > 0) {
        row.put("added_count", addedCount);
      }
      if (backup != null) {
        row.put("backup", backup.toString());
      }
      if (detail != null && !detail.trim().isEmpty()) {
        row.put("detail", truncate(redact(account, detail), 700));
      }
      Files.writeString(config.ledger, Json.stringify(row) + "\n", StandardCharsets.UTF_8,
          java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
      chmod600(config.ledger);
    }

    private void recordRun(String status, String detail, int dbCount) throws IOException {
      LinkedHashMap<String, Object> row = new LinkedHashMap<>();
      row.put("at", Instant.now().toString());
      row.put("scope", "run");
      row.put("status", status);
      row.put("db_count", dbCount);
      if (detail != null && !detail.trim().isEmpty()) {
        row.put("detail", truncate(detail, 700));
      }
      Files.writeString(config.ledger, Json.stringify(row) + "\n", StandardCharsets.UTF_8,
          java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
      chmod600(config.ledger);
    }
  }

  static final class AccountRow {
    final int index;
    final int sourceLine;
    final String email;
    final String password;
    final String otpSecret;

    AccountRow(int index, int sourceLine, String email, String password, String otpSecret) {
      this.index = index;
      this.sourceLine = sourceLine;
      this.email = email;
      this.password = password;
      this.otpSecret = otpSecret;
    }

    static AccountRow parse(String line, int sourceLine) {
      String trimmed = line == null ? "" : line.trim();
      if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        return null;
      }
      int first = trimmed.indexOf(':');
      int last = trimmed.lastIndexOf(':');
      if (first <= 0 || last <= first) {
        throw new IllegalArgumentException("source line " + sourceLine
            + " must use username:password:otp-secret");
      }
      String email = trimmed.substring(0, first).trim();
      String password = trimmed.substring(first + 1, last);
      String otp = trimmed.substring(last + 1).trim();
      return new AccountRow(sourceLine, sourceLine, email, password, otp);
    }

    AccountRow withIndex(int index) {
      return new AccountRow(index, sourceLine, email, password, otpSecret);
    }

    void validate() {
      if (email.isEmpty() || !email.contains("@")) {
        throw new IllegalArgumentException("source line " + sourceLine + " has an invalid username/email");
      }
      if (password.isEmpty()) {
        throw new IllegalArgumentException("source line " + sourceLine + " has an empty password");
      }
      Totp.validateSecret(otpSecret);
    }

  }

  private static final class Config {
    Path input;
    Path db;
    Path ledger;
    Path bandwidthOut;
    boolean stdin;
    int start = 1;
    int end = -1;
    BrowserEngine browserEngine = BrowserEngine.JCEF;
    String browserPath = "";
    Path userDataDir;
    Path jcefDir;
    int devtoolsPort = 0;
    long humanCheckWaitMs = DEFAULT_HUMAN_CHECK_WAIT_MS;
    boolean keepBrowserOpen;
    boolean dryRun;
    boolean allowDreamBotRunning;
    String mailCodeHelper = "";
    Boolean headless;

    boolean isHeadless() {
      return headless == null ? browserEngine == BrowserEngine.JCEF : headless;
    }

    static Config parse(List<String> argv) {
      Config config = new Config();
      boolean engineExplicit = false;
      for (int i = 0; i < argv.size(); i++) {
        String arg = argv.get(i);
        switch (arg) {
          case "--input":
            config.input = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--stdin":
            config.stdin = true;
            break;
          case "--db":
            config.db = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--ledger":
            config.ledger = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--start":
            config.start = Integer.parseInt(requireValue(argv, ++i, arg));
            break;
          case "--end":
            config.end = Integer.parseInt(requireValue(argv, ++i, arg));
            break;
          case "--browser-engine":
            config.browserEngine = BrowserEngine.parse(requireValue(argv, ++i, arg));
            engineExplicit = true;
            break;
          case "--embedded-browser":
            config.browserEngine = BrowserEngine.JCEF;
            engineExplicit = true;
            break;
          case "--system-browser":
            config.browserEngine = BrowserEngine.SYSTEM;
            engineExplicit = true;
            break;
          case "--browser":
            config.browserPath = requireValue(argv, ++i, arg);
            if (!engineExplicit) {
              config.browserEngine = BrowserEngine.SYSTEM;
            }
            break;
          case "--user-data-dir":
            config.userDataDir = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--jcef-dir":
            config.jcefDir = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--devtools-port":
            config.devtoolsPort = Integer.parseInt(requireValue(argv, ++i, arg));
            break;
          case "--human-check-wait-ms":
            config.humanCheckWaitMs = Long.parseLong(requireValue(argv, ++i, arg));
            break;
          case "--mail-code-helper":
            config.mailCodeHelper = requireValue(argv, ++i, arg);
            break;
          case "--keep-browser-open":
            config.keepBrowserOpen = true;
            break;
          case "--allow-dreambot-running":
            config.allowDreamBotRunning = true;
            break;
          case "--headless":
            config.headless = true;
            break;
          case "--headed":
            config.headless = false;
            break;
          case "--dry-run":
            config.dryRun = true;
            break;
          default:
            throw new IllegalArgumentException("unknown option: " + arg);
        }
      }
      if (!config.stdin && config.input == null) {
        throw new IllegalArgumentException("--input or --stdin is required");
      }
      return config;
    }
  }

  private static final class Gui {
    private final JTextField input = new JTextField();
    private final JTextField db = new JTextField();
    private final JComboBox<String> engine = new JComboBox<>(new String[] {"Embedded JCEF", "System Chrome/Edge"});
    private final JCheckBox headless = new JCheckBox("Minimized/internal browser", true);
    private final JCheckBox keepBrowserOpen = new JCheckBox("Keep browser open");
    private final JProgressBar progress = new JProgressBar();
    private final JLabel status = new JLabel("Idle");
    private final JTextArea log = new JTextArea(16, 82);
    private final JButton start = new JButton("Start");
    private final JButton pause = new JButton("Pause");
    private final JButton stop = new JButton("Stop");
    private SwingWorker<Integer, String> worker;
    private GuiRunControl runControl;

    void show() {
      JFrame frame = new JFrame("DreamBot Jagex Bulk Importer");
      frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      frame.setLayout(new BorderLayout(8, 8));

      JPanel form = new JPanel(new GridBagLayout());
      addRow(form, 0, "Accounts file", input, chooserButton(input, false));
      addRow(form, 1, "accounts.db", db, chooserButton(db, false));
      addRow(form, 2, "Browser engine", engine);
      engine.addActionListener(event -> updateEngineFields());
      updateEngineFields();

      JPanel buttons = new JPanel();
      start.addActionListener(event -> start());
      pause.addActionListener(event -> togglePause());
      stop.addActionListener(event -> stop());
      pause.setEnabled(false);
      stop.setEnabled(false);
      buttons.add(headless);
      buttons.add(keepBrowserOpen);
      buttons.add(start);
      buttons.add(pause);
      buttons.add(stop);

      log.setEditable(false);
      progress.setStringPainted(true);
      progress.setMinimum(0);
      progress.setValue(0);

      JPanel south = new JPanel(new BorderLayout(8, 4));
      south.add(buttons, BorderLayout.NORTH);
      south.add(progress, BorderLayout.CENTER);
      south.add(status, BorderLayout.SOUTH);

      frame.add(form, BorderLayout.NORTH);
      frame.add(new JScrollPane(log), BorderLayout.CENTER);
      frame.add(south, BorderLayout.SOUTH);
      frame.pack();
      frame.setLocationRelativeTo(null);
      frame.setVisible(true);
    }

    private JButton chooserButton(JTextField target, boolean save) {
      JButton button = new JButton("Browse");
      button.addActionListener(event -> {
        JFileChooser chooser = new JFileChooser();
        int result = save ? chooser.showSaveDialog(null) : chooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
          target.setText(chooser.getSelectedFile().toString());
        }
      });
      return button;
    }

    private void addRow(JPanel panel, int y, String label, JTextField field, JButton browse) {
      GridBagConstraints c = new GridBagConstraints();
      c.gridy = y;
      c.insets = new Insets(4, 6, 4, 6);
      c.anchor = GridBagConstraints.WEST;
      panel.add(new JLabel(label), c);
      c.gridx = 1;
      c.weightx = 1;
      c.fill = GridBagConstraints.HORIZONTAL;
      panel.add(field, c);
      c.gridx = 2;
      c.weightx = 0;
      c.fill = GridBagConstraints.NONE;
      panel.add(browse, c);
    }

    private void addRow(JPanel panel, int y, String label, JComboBox<String> comboBox) {
      GridBagConstraints c = new GridBagConstraints();
      c.gridy = y;
      c.insets = new Insets(4, 6, 4, 6);
      c.anchor = GridBagConstraints.WEST;
      panel.add(new JLabel(label), c);
      c.gridx = 1;
      c.gridwidth = 2;
      c.weightx = 1;
      c.fill = GridBagConstraints.HORIZONTAL;
      panel.add(comboBox, c);
    }

    private void updateEngineFields() {
      boolean embedded = engine.getSelectedIndex() == 0;
      headless.setText(embedded ? "Minimized/internal browser" : "Headless system browser");
    }

    private void start() {
      if (worker != null && !worker.isDone()) {
        return;
      }
      Config config = new Config();
      config.input = input.getText().trim().isEmpty() ? null : Paths.get(input.getText().trim());
      config.db = db.getText().trim().isEmpty() ? null : Paths.get(db.getText().trim());
      config.browserEngine = engine.getSelectedIndex() == 0 ? BrowserEngine.JCEF : BrowserEngine.SYSTEM;
      config.headless = headless.isSelected();
      config.keepBrowserOpen = keepBrowserOpen.isSelected();

      GuiRunControl control = new GuiRunControl();
      runControl = control;
      start.setEnabled(false);
      pause.setEnabled(true);
      pause.setText("Pause");
      stop.setEnabled(true);
      log.setText("");
      log.setCaretPosition(0);
      progress.setIndeterminate(true);
      progress.setValue(0);
      progress.setString("Starting");
      status.setText("Starting");
      worker = new SwingWorker<>() {
        @Override
        protected Integer doInBackground() throws Exception {
          Progress progressReporter = new Progress() {
            @Override
            public void total(int total) {
              SwingUtilities.invokeLater(() -> {
                progress.setIndeterminate(false);
                progress.setMaximum(Math.max(1, total));
                progress.setValue(0);
                progress.setString("0 / " + total);
                status.setText("0 / " + total + " accounts processed");
              });
            }

            @Override
            public void row(int completed, int total, String message) {
              SwingUtilities.invokeLater(() -> {
                progress.setIndeterminate(false);
                progress.setMaximum(Math.max(1, total));
                progress.setValue(Math.max(0, Math.min(completed, total)));
                progress.setString(completed + " / " + total);
                status.setText(message);
              });
            }
          };
          return new Importer(config, this::publish, progressReporter, control).run();
        }

        @Override
        protected void process(List<String> chunks) {
          for (String chunk : chunks) {
            appendLog(chunk);
          }
        }

        @Override
        protected void done() {
          start.setEnabled(true);
          pause.setEnabled(false);
          pause.setText("Pause");
          stop.setEnabled(false);
          runControl = null;
          boolean openLedger = false;
          try {
            if (isCancelled() || control.isStopped()) {
              appendLog("Stopped");
              status.setText("Stopped");
              progress.setIndeterminate(false);
              return;
            }
            int exitCode = get();
            appendLog("Finished with exit code " + exitCode);
            status.setText(exitCode == 0 ? "Finished successfully" : "Finished with failures");
            openLedger = true;
            if (!progress.isIndeterminate() && progress.getMaximum() > 0) {
              progress.setValue(progress.getMaximum());
              progress.setString(progress.getValue() + " / " + progress.getMaximum());
            }
          } catch (CancellationException exception) {
            appendLog("Stopped");
            status.setText("Stopped");
            progress.setIndeterminate(false);
          } catch (Exception exception) {
            appendLog("Failed: " + exception.getMessage());
            status.setText("Failed: " + exception.getMessage());
            progress.setIndeterminate(false);
            openLedger = true;
          } finally {
            if (openLedger) {
              openLedger(config.ledger);
            }
          }
        }
      };
      worker.execute();
    }

    private void togglePause() {
      GuiRunControl control = runControl;
      if (control == null) {
        return;
      }
      boolean paused = control.togglePaused();
      pause.setText(paused ? "Resume" : "Pause");
      status.setText(paused ? "Paused" : "Running");
      appendLog(paused ? "Paused" : "Resumed");
    }

    private void stop() {
      GuiRunControl control = runControl;
      if (control != null) {
        control.stop();
      }
      if (worker != null) {
        worker.cancel(true);
      }
      pause.setEnabled(false);
      stop.setEnabled(false);
      status.setText("Stopping");
      appendLog("Stop requested");
    }

    private void appendLog(String line) {
      log.append(line + "\n");
      log.setCaretPosition(log.getDocument().getLength());
    }

    private void openLedger(Path ledger) {
      if (ledger == null || !Files.isRegularFile(ledger)) {
        appendLog("Ledger file was not created");
        return;
      }
      try {
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")) {
          new ProcessBuilder("notepad.exe", ledger.toAbsolutePath().toString()).start();
        } else if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
          Desktop.getDesktop().open(ledger.toFile());
        } else {
          appendLog("Ledger: " + ledger.toAbsolutePath());
          return;
        }
        appendLog("Opened ledger: " + ledger.toAbsolutePath());
      } catch (IOException exception) {
        appendLog("Could not open ledger: " + exception.getMessage());
      }
    }
  }

  private static final class GuiRunControl implements RunControl {
    private boolean paused;
    private boolean stopped;

    synchronized boolean togglePaused() {
      paused = !paused;
      notifyAll();
      return paused;
    }

    synchronized boolean isStopped() {
      return stopped;
    }

    synchronized void stop() {
      stopped = true;
      paused = false;
      notifyAll();
    }

    @Override
    public void checkpoint() {
      synchronized (this) {
        while (paused && !stopped) {
          try {
            wait(250L);
          } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new CancellationException("interrupted");
          }
        }
        if (stopped) {
          throw new CancellationException("stopped");
        }
      }
    }
  }

  private static void guardDreamBotNotRunning(Config config, Consumer<String> log) {
    if (config.allowDreamBotRunning) {
      log.accept("DreamBot process guard bypassed; only use this for isolated DB copies");
      return;
    }
    int matches = 0;
    long currentPid = ProcessHandle.current().pid();
    for (ProcessHandle process : ProcessHandle.allProcesses().toArray(ProcessHandle[]::new)) {
      if (process.pid() == currentPid) {
        continue;
      }
      if (looksLikeDreamBotProcess(process.info())) {
        matches++;
      }
    }
    if (matches > 0) {
      throw new IllegalStateException("DreamBot appears to be running. Close DreamBot before writing accounts.db, "
          + "then rerun the importer. Use --allow-dreambot-running only for an isolated DB copy.");
    }
  }

  private static void guardAccountsDbNotOpen(Path db) {
    Path absolute = db.toAbsolutePath().normalize();
    if (!Files.isRegularFile(absolute)) {
      return;
    }
    List<Long> openPids = accountsDbOpenPids(absolute);
    if (!openPids.isEmpty()) {
      throw new IllegalStateException("accounts.db is open by another process (pid"
          + (openPids.size() == 1 ? "" : "s") + " " + joinPids(openPids)
          + "). Close DreamBot or any account-manager/editor using accounts.db, then rerun the importer.");
    }
    probeExclusiveDbAccess(absolute);
  }

  private static List<Long> accountsDbOpenPids(Path db) {
    LinkedHashSet<Long> pids = new LinkedHashSet<>();
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.contains("win")) {
      addWindowsHandlePids(db, pids);
    } else {
      Path lsof = findCommand("lsof");
      if (lsof != null) {
        addPidMatches(pids, runCommand(List.of(lsof.toString(), "-t", db.toString())), Pattern.compile("\\b(\\d+)\\b"));
      }
      Path fuser = findCommand("fuser");
      if (fuser != null) {
        addPidMatches(pids, runCommand(List.of(fuser.toString(), db.toString())), Pattern.compile("\\b(\\d+)\\b"));
      }
    }
    long currentPid = ProcessHandle.current().pid();
    pids.remove(currentPid);
    return new ArrayList<>(pids);
  }

  private static void addWindowsHandlePids(Path db, Set<Long> pids) {
    String explicit = System.getenv("DREAMBOT_JAGEX_IMPORTER_HANDLE_EXE");
    Path handle = explicit == null || explicit.isBlank()
        ? findCommand("handle64.exe", "handle.exe")
        : Paths.get(explicit);
    if (handle == null || !Files.isRegularFile(handle)) {
      return;
    }
    String output = runCommand(List.of(handle.toString(), "-nobanner", "-accepteula", db.toString()));
    addPidMatches(pids, output, Pattern.compile("(?i)\\bpid:\\s*(\\d+)\\b"));
  }

  private static void probeExclusiveDbAccess(Path db) {
    try (FileChannel channel = FileChannel.open(db, StandardOpenOption.WRITE);
        FileLock lock = channel.tryLock()) {
      if (lock == null) {
        throw new IllegalStateException("accounts.db is locked by another process. Close DreamBot or any "
            + "account-manager/editor using accounts.db, then rerun the importer.");
      }
    } catch (OverlappingFileLockException exception) {
      throw new IllegalStateException("accounts.db is already locked in this process", exception);
    } catch (IOException exception) {
      throw new IllegalStateException("accounts.db could not be opened for exclusive write access. Close DreamBot "
          + "or any account-manager/editor using accounts.db, then rerun the importer. Detail: "
          + exception.getMessage(), exception);
    }
  }

  private static Path findCommand(String... names) {
    String path = System.getenv("PATH");
    if (path == null || path.isBlank()) {
      return null;
    }
    for (String dir : path.split(Pattern.quote(File.pathSeparator))) {
      if (dir == null || dir.isBlank()) {
        continue;
      }
      for (String name : names) {
        Path candidate = Paths.get(dir, name);
        if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
          return candidate;
        }
      }
    }
    return null;
  }

  private static String runCommand(List<String> command) {
    try {
      Process process = new ProcessBuilder(command).start();
      boolean finished = process.waitFor(3, TimeUnit.SECONDS);
      if (!finished) {
        process.destroyForcibly();
        return "";
      }
      return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    } catch (Exception ignored) {
      return "";
    }
  }

  private static void addPidMatches(Set<Long> pids, String output, Pattern pattern) {
    Matcher matcher = pattern.matcher(output == null ? "" : output);
    while (matcher.find()) {
      try {
        pids.add(Long.parseLong(matcher.group(1)));
      } catch (NumberFormatException ignored) {
        // Ignore malformed tool output.
      }
    }
  }

  private static String joinPids(List<Long> pids) {
    StringBuilder out = new StringBuilder();
    for (Long pid : pids) {
      if (out.length() > 0) {
        out.append(", ");
      }
      out.append(pid);
    }
    return out.toString();
  }

  private static boolean looksLikeDreamBotProcess(ProcessHandle.Info info) {
    StringBuilder text = new StringBuilder();
    String command = info.command().orElse("");
    text.append(command).append(' ');
    info.arguments().ifPresent(arguments -> {
      for (String argument : arguments) {
        text.append(argument).append(' ');
      }
    });
    String lower = text.toString().toLowerCase(Locale.ROOT);
    if (!lower.contains("dreambot") || lower.contains("dreambot-jagex-bulk-importer")) {
      return false;
    }
    if (lower.contains("dreambot-mcp.jar")
        || lower.contains("dreambot_mcp.py")
        || lower.contains("dreambot_harness.py")
        || lower.contains("dreambot-account-factory")
        || lower.contains("dreambot-task-harness")
        || lower.contains("dreambot-run-task-queue")
        || lower.contains("panel/server.py")) {
      return false;
    }
    String commandBase = "";
    if (!command.isBlank()) {
      try {
        commandBase = Paths.get(command).getFileName().toString().toLowerCase(Locale.ROOT);
      } catch (Exception ignored) {
        commandBase = command.toLowerCase(Locale.ROOT);
      }
    }
    return lower.contains("botdata")
        || lower.contains("client.jar")
        || lower.contains("dreambot.jar")
        || lower.contains("dreambotlauncher")
        || "dreambot".equals(commandBase)
        || "dreambot.exe".equals(commandBase);
  }

  private static void warnIfDbPathLooksUnexpected(Path db, Consumer<String> log) {
    String normalized = db.toAbsolutePath().normalize().toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    if (!normalized.endsWith("/botdata/accounts.db")) {
      log.accept("Warning: selected accounts.db is not under a DreamBot BotData directory; verify this is the DB DreamBot loads");
    }
  }

  private static Path defaultLedger(Path db) {
    Path parent = db.toAbsolutePath().getParent();
    if (parent == null) {
      parent = Paths.get(".");
    }
    return parent.resolve("jagex-bulk-import-" + FILE_STAMP.format(Instant.now()) + ".jsonl");
  }

  private static Path defaultBandwidth(Path ledger) {
    String name = ledger.getFileName() == null ? "jagex-bulk-import.jsonl" : ledger.getFileName().toString();
    String stem = name.endsWith(".jsonl") ? name.substring(0, name.length() - 6) : name;
    Path parent = ledger.toAbsolutePath().getParent();
    if (parent == null) {
      parent = Paths.get(".");
    }
    return parent.resolve(stem + ".bandwidth.json");
  }

  private static String requireValue(List<String> argv, int index, String option) {
    if (index >= argv.size()) {
      throw new IllegalArgumentException(option + " requires a value");
    }
    return argv.get(index);
  }

  private static Map<String, String> parseOptions(List<String> argv) {
    LinkedHashMap<String, String> options = new LinkedHashMap<>();
    for (int i = 0; i < argv.size(); i++) {
      String arg = argv.get(i);
      if (!arg.startsWith("--")) {
        throw new IllegalArgumentException("unknown argument: " + arg);
      }
      String key = arg.substring(2);
      if (i + 1 >= argv.size() || argv.get(i + 1).startsWith("--")) {
        options.put(key, "true");
      } else {
        options.put(key, requireValue(argv, ++i, arg));
      }
    }
    return options;
  }

  private static boolean isTruthy(String value) {
    switch (String.valueOf(value == null ? "" : value).trim().toLowerCase(Locale.ROOT)) {
      case "0":
      case "off":
      case "false":
      case "no":
      case "disabled":
      case "":
        return false;
      default:
        return true;
    }
  }

  private static String pageStateScript() {
    return "(() => {"
        + "const normalize=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const actions=Array.from(document.querySelectorAll('button,input[type=\"submit\"],a,[role=\"button\"],label'))"
        + ".filter(visible).map((el)=>normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent)).filter(Boolean).slice(0,40);"
        + "const inputs=Array.from(document.querySelectorAll('input')).filter(visible).map((input)=>({type:input.type||'',name:input.name||'',id:input.id||'',autocomplete:input.autocomplete||'',placeholder:input.placeholder||''})).slice(0,20);"
        + "const text=normalize(document.body?document.body.innerText:'');"
        + "return {href:location.href,title:document.title,text:text.slice(0,900),actions,inputs};"
        + "})()";
  }

  private static String redact(AccountRow account, String text) {
    if (text == null) {
      return "";
    }
    String redacted = text;
    if (account != null) {
      redacted = redactValues(redacted, account.email, account.password, account.otpSecret);
    }
    return redacted;
  }

  private static String redactValues(String text, String... values) {
    String redacted = text == null ? "" : text;
    if (values == null) {
      return redacted;
    }
    for (String value : values) {
      if (value != null && !value.isEmpty()) {
        redacted = redacted.replace(value, "<redacted>");
      }
    }
    return redacted;
  }

  private static String truncate(String value, int max) {
    return value.length() <= max ? value : value.substring(0, max);
  }

  private static void chmod600(Path path) {
    try {
      Files.setPosixFilePermissions(path, java.util.Set.of(
          java.nio.file.attribute.PosixFilePermission.OWNER_READ,
          java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
    } catch (Exception ignored) {
      // Windows.
    }
  }
}
