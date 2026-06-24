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
import java.util.Collections;
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
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;

public final class DreamBotJagexBulkImporter {
  private static final long DEFAULT_HUMAN_CHECK_WAIT_MS = 300_000L;
  private static final long DEFAULT_RATE_LIMIT_COOLDOWN_MS = TimeUnit.HOURS.toMillis(3);
  private static final int MAX_TEMPORARY_OAUTH_ATTEMPTS =
      positiveEnvInt("DREAMBOT_JAGEX_IMPORTER_TEMP_OAUTH_ATTEMPTS", 4);
  private static final Progress NO_PROGRESS = new Progress() { };
  private static final DateTimeFormatter FILE_STAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

  private DreamBotJagexBulkImporter() {
  }

  private static int positiveEnvInt(String name, int defaultValue) {
    String raw = String.valueOf(System.getenv(name) == null ? "" : System.getenv(name)).trim();
    if (raw.isEmpty()) {
      return defaultValue;
    }
    try {
      return Math.max(1, Integer.parseInt(raw));
    } catch (NumberFormatException ignored) {
      return defaultValue;
    }
  }

  public static void main(String[] args) {
    try {
      int exit = runMain(args);
      if (exit != 0) {
        System.exit(exit);
      }
    } catch (Throwable throwable) {
      System.err.println(sanitizeDiagnostic(
          throwable.getMessage() == null ? throwable.toString() : throwable.getMessage()));
      System.exit(1);
    }
  }

  private static int runMain(String[] args) throws Exception {
    List<String> argv = new ArrayList<>(Arrays.asList(args));
    if (argv.isEmpty() || "--gui".equals(argv.get(0))) {
      if (!argv.isEmpty()) {
        requireArgCount(argv, 1, "--gui");
      }
      SwingUtilities.invokeLater(() -> new Gui().show());
      return 0;
    }
    if ("--help".equals(argv.get(0)) || "-h".equals(argv.get(0))) {
      requireArgCount(argv, 1, argv.get(0));
      printUsage();
      return 0;
    }
    if ("--totp".equals(argv.get(0))) {
      requireArgCount(argv, 2, "--totp");
      Totp.Code code = generateFreshTotp(argv.get(1));
      LinkedHashMap<String, Object> out = new LinkedHashMap<>();
      out.put("code", code.value);
      out.put("remaining_seconds", code.remainingSeconds);
      out.put("period", code.period);
      System.out.println(Json.stringify(out));
      return 0;
    }
    if ("--db-info".equals(argv.get(0))) {
      requireArgCount(argv, 2, "--db-info");
      Path db = Paths.get(requireValue(argv, 1, "--db-info"));
      DreamBotAccountStore.Info info = DreamBotAccountStore.info(db);
      LinkedHashMap<String, Object> out = new LinkedHashMap<>();
      out.put("ok", true);
      out.put("accounts", info.count);
      out.put("codec", info.codec);
      out.put("aad", info.aad);
      System.out.println(Json.stringify(out));
      return 0;
    }
    if ("--db-browser".equals(argv.get(0))) {
      requireArgCount(argv, 2, "--db-browser");
      Path db = Paths.get(requireValue(argv, 1, "--db-browser"));
      SwingUtilities.invokeLater(() -> showAccountsDbBrowser(db));
      return 0;
    }
    if ("--browser-check".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()), Set.of(
          "jcef-dir", "devtools-port", "headless", "headed", "proxy-file"));
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      boolean headless = browserHeadless(options, true);
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      ProxyConfig proxy = firstProxy(proxyListFromOptions(options));
      try (BrowserSession session = launchBrowser("jcef", "", jcefDir, port, false, headless, null, proxy,
          message -> System.err.println(sanitizeDiagnostic(message)))) {
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("headless", session.headless);
        out.put("port", session.port);
        out.put("targets", CdpClient.targets(session.endpoint).size());
        System.out.println(Json.stringify(out));
      }
      return 0;
    }
    if ("--page-state".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()), Set.of("devtools-port"));
      int port = Integer.parseInt(options.getOrDefault("devtools-port", "0"));
      if (port <= 0) {
        throw new IllegalArgumentException("--page-state requires --devtools-port");
      }
      try (CdpClient cdp = CdpClient.connect(CdpClient.pageWebSocket("http://127.0.0.1:" + port))) {
        cdp.send("Runtime.enable");
        Object value = cdp.evaluate(pageStateScript());
        System.out.println(sanitizeDiagnostic(Json.stringify(value)));
      }
      return 0;
    }
    if ("--enroll-only".equals(argv.get(0))) {
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()), Set.of(
          "input", "account", "jcef-dir",
          "devtools-port", "human-check-wait-ms", "headless", "headed", "ledger",
          "mail-code-helper", "proxy-file"));
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
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      long humanWait = options.containsKey("human-check-wait-ms")
          ? Long.parseLong(options.get("human-check-wait-ms")) : 300_000L;
      boolean headless = browserHeadless(options, true);
      Path ledger = options.containsKey("ledger") ? Paths.get(options.get("ledger")) : null;
      Path bandwidthOut = ledger == null ? null : defaultBandwidth(ledger);
      ProxyConfig proxy = firstProxy(proxyListFromOptions(options));
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
          try (BrowserSession browser = launchBrowser("jcef", "", jcefDir, port, false, headless, null, proxy,
              message -> System.err.println(sanitizeDiagnostic("row " + displayIndex + " " + message)))) {
            JagexCdpAutomation automation = new JagexCdpAutomation(browser, humanWait,
                message -> System.err.println(sanitizeDiagnostic("row " + displayIndex + " " + message)));
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
            String message = sanitizeDiagnostic(exception.getMessage() == null ? exception.toString() : exception.getMessage(),
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
      Map<String, String> options = parseOptions(argv.subList(1, argv.size()), Set.of(
          "account", "jcef-dir",
          "devtools-port", "human-check-wait-ms", "headless", "headed", "mail-code-helper",
          "proxy-file"));
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
      Path jcefDir = options.containsKey("jcef-dir") ? Paths.get(options.get("jcef-dir")) : null;
      int port = options.containsKey("devtools-port") ? Integer.parseInt(options.get("devtools-port")) : 0;
      long humanWait = options.containsKey("human-check-wait-ms")
          ? Long.parseLong(options.get("human-check-wait-ms")) : 300_000L;
      boolean headless = browserHeadless(options, true);
      String mailCodeHelper = options.getOrDefault("mail-code-helper",
          "/root/projects/dreambot/tools/2b2m_mail_code.py");
      ProxyConfig proxy = firstProxy(proxyListFromOptions(options));
      try (BrowserSession browser = launchBrowser("jcef", "", jcefDir, port, false, headless, null, proxy,
          message -> System.err.println(sanitizeDiagnostic("disable-email " + message)))) {
        JagexCdpAutomation automation = new JagexCdpAutomation(browser, humanWait,
            message -> System.err.println(sanitizeDiagnostic("disable-email " + message)));
        String result = automation.disableEmailOnly(email, password, secret, mailCodeHelper);
        System.out.println(result);
        return 0;
      } catch (Exception exception) {
        String message = sanitizeDiagnostic(exception.getMessage() == null ? exception.toString() : exception.getMessage(),
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

  private static boolean browserHeadless(Map<String, String> options, boolean defaultValue) {
    if (options.containsKey("headed")) {
      return !isTruthy(options.get("headed"));
    }
    if (options.containsKey("headless")) {
      return isTruthy(options.get("headless"));
    }
    return defaultValue;
  }

  private static void printUsage() {
    System.out.println(String.join("\n",
        "Usage:",
        "  java -jar dreambot-jagex-bulk-importer.jar --input accounts.txt [--db accounts.db] [options]",
        "  java -jar dreambot-jagex-bulk-importer.jar --stdin [--db accounts.db] [options]",
        "  java -jar dreambot-jagex-bulk-importer.jar --gui",
        "  java -jar dreambot-jagex-bulk-importer.jar --db-info accounts.db",
        "  java -jar dreambot-jagex-bulk-importer.jar --db-browser accounts.db",
        "  java -jar dreambot-jagex-bulk-importer.jar --browser-check",
        "  java -jar dreambot-jagex-bulk-importer.jar --page-state --devtools-port N",
        "  java -jar dreambot-jagex-bulk-importer.jar --enroll-only --input accounts.txt",
        "  java -jar dreambot-jagex-bulk-importer.jar --disable-email-only --account email:password:secret",
        "  java -jar dreambot-jagex-bulk-importer.jar --totp SECRET",
        "",
        "Input rows use: username:password:otp-secret",
        "",
        "Import options:",
        "  --input PATH              Account list file",
        "  --stdin                   Read account rows from stdin",
        "  --db PATH                 DreamBot BotData/accounts.db to update; auto-detected if omitted",
        "  --start N                 First 1-based source row to import (default: 1)",
        "  --end N                   Last 1-based source row to import (default: last row)",
        "  --ledger PATH             Non-secret JSONL result ledger",
        "  --browser-engine NAME     Compatibility alias accepted for system or embedded browser callers",
        "  --browser PATH            Compatibility alias accepted for callers that pass a browser binary",
        "  --user-data-dir PATH      Compatibility alias accepted for callers that reuse a browser profile",
        "  --system-browser          Compatibility alias for --browser-engine system",
        "  --embedded-browser        Compatibility alias for --browser-engine jcef",
        "  --jcef-dir PATH           Embedded JCEF native-runtime cache directory",
        "  --headless                Start embedded JCEF minimized/internal",
        "  --headed                  Show the embedded JCEF browser window",
        "  --devtools-port N         Browser DevTools port (default: auto)",
        "  --human-check-wait-ms N   Max wait for browser challenge pages (default: 300000)",
        "  --rate-limit-cooldown-minutes N  Wait before retrying after Jagex rate limits (default: 180)",
        "  --proxy-file PATH         Proxy list file; one proxy per line as server|username|password",
        "  --keep-browser-open       Leave browser open after import attempts",
        "  --allow-dreambot-running Bypass the DreamBot process guard for isolated DB copies",
        "  --dry-run                 Parse rows, validate TOTP, and decrypt DB without importing",
        "  --mail-code-helper PATH   Helper used when login needs an email verification code",
        "",
        "Utility options:",
        "  --db-info PATH            Print encrypted accounts.db count, codec, and AAD",
        "  --db-browser PATH         Open a full accounts.db table view",
        "  --browser-check           Launch embedded JCEF and report DevTools status",
        "  --page-state              Print current page state from --devtools-port",
        "  --enroll-only             Enroll authenticators; accepts --input or --account",
        "  --disable-email-only      Disable email MFA for --account email:password:secret",
        "  --totp SECRET             Utility mode: print the current generated TOTP code"));
  }

  private interface Progress {
    default void total(int total) {
    }

    default void row(int completed, int total, String message) {
    }
  }

  private static BrowserSession launchBrowser(String browserEngine, String browserPath, Path jcefDir,
      int devtoolsPort, boolean keepBrowserOpen, boolean headless, Path userDataDir,
      ProxyConfig proxy, Consumer<String> log) throws Exception {
    if ("system".equalsIgnoreCase(String.valueOf(browserEngine))) {
      return BrowserLauncher.launch(browserPath, devtoolsPort, keepBrowserOpen, headless, userDataDir, proxy);
    }
    return JcefBrowserLauncher.launch(jcefDir, devtoolsPort, keepBrowserOpen, headless, log, proxy);
  }

  private static final class Importer {
    private final Config config;
    private final Consumer<String> log;
    private final Progress progress;
    private final RunControl control;
    private final DreamBotAccountStore.BackupContext backupContext = DreamBotAccountStore.backupContext();
    private final List<ProxyConfig> proxies;
    private int proxyIndex;
    private int expectedDbCount = -1;

    Importer(Config config, Consumer<String> log) {
      this(config, log, NO_PROGRESS);
    }

    Importer(Config config, Consumer<String> log, Progress progress) {
      this(config, log, progress, RunControl.NONE);
    }

    Importer(Config config, Consumer<String> log, Progress progress, RunControl control) {
      this.config = config;
      this.log = DiagnosticSanitizer.consumer(log);
      this.progress = progress == null ? NO_PROGRESS : progress;
      this.control = control == null ? RunControl.NONE : control;
      this.proxies = config.proxies == null ? List.of() : new ArrayList<>(config.proxies);
    }

    int run() throws Exception {
      List<AccountRow> rows = config.stdin ? readRowsFromStdin() : readRows(config.input);
      if (rows.isEmpty()) {
        throw new IllegalArgumentException("no account rows were found");
      }
      if (config.db == null) {
        config.db = autoDetectAccountsDb();
        if (config.db != null) {
          log.accept("Auto-detected accounts.db: " + config.db);
        }
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
        log.accept("DB opened and decoded");
        log.accept("Loaded " + rows.size() + " account row(s); importing rows " + config.start + "-" + end);
        log.accept("Ledger: " + config.ledger + " (JSONL row-status audit; not used as the account database)");
        log.accept("Bandwidth: " + config.bandwidthOut + " (JSON summary for browser/API traffic)");
        if (!config.dryRun) {
          log.accept(browserSummary(config));
        }

        int failures = 0;
        int total = end - config.start + 1;
        progress.total(total);
        for (int rowIndex = config.start; rowIndex <= end; rowIndex++) {
          control.checkpoint();
          AccountRow account = rows.get(rowIndex - 1).withIndex(rowIndex);
          int completedBefore = rowIndex - config.start;
          progress.row(completedBefore, total, "Starting row " + account.index);
          try {
            String status = importOne(account);
            progress.row(completedBefore + 1, total, "Row " + account.index + " " + status);
          } catch (CancellationException exception) {
            throw exception;
          } catch (JagexCdpAutomation.TerminalAuthException exception) {
            String detail = sanitizeDiagnostic(account,
                exception.getMessage() == null ? exception.toString() : exception.getMessage());
            log.accept("row " + account.index + " skipped: " + detail);
            record(account, exception.status(), detail, 0, null);
            progress.row(completedBefore + 1, total, "Row " + account.index + " " + exception.status());
          } catch (Exception exception) {
            failures++;
            String detail = sanitizeDiagnostic(account,
                exception.getMessage() == null ? exception.toString() : exception.getMessage());
            String exceptionType = exception.getClass().getName();
            java.io.StringWriter stackBuffer = new java.io.StringWriter();
            exception.printStackTrace(new java.io.PrintWriter(stackBuffer));
            log.accept("row " + account.index + " failed: " + detail);
            log.accept("row " + account.index + " failed type: " + exceptionType);
            log.accept("row " + account.index + " failed stack: "
                + truncate(sanitizeDiagnostic(account, stackBuffer.toString()), 4000));
            record(account, "failed", detail, 0, null);
            progress.row(completedBefore + 1, total, "Row " + account.index + " failed");
          }
        }
        verifyFinalDbCount();
        recordRun(failures == 0 ? "finished" : "finished_with_failures", "Final DB verified");
        log.accept("Final DB verified");
        return failures == 0 ? 0 : 1;
      } finally {
        if (config.bandwidthOut != null) {
          BandwidthAudit.write(config.bandwidthOut);
          chmod600(config.bandwidthOut);
        }
      }
    }

    private String importOne(AccountRow account) throws Exception {
      control.checkpoint();
      account.validate();
      log.accept("row " + account.index + " start");
      log.accept("row " + account.index + " input validated; OTP secret accepted");
      if (!config.dryRun && DreamBotAccountStore.containsLogin(config.db, account.email)) {
        log.accept("row " + account.index + " already present in accounts.db; skipping browser login");
        record(account, "already_present", "matched existing accounts.db login before browser login", 0, null);
        return "already_present";
      }
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
        ProxyConfig proxy = activeProxy();
        JagexOAuthClient oauth = new JagexOAuthClient(message -> log.accept(message), proxy);
        try (BrowserSession browser = launchBrowser(config.browserEngine, config.browserPath, config.jcefDir,
            config.devtoolsPort, config.keepBrowserOpen, config.isHeadless(), config.userDataDir, proxy,
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
          record(account, "added", "account store updated", result.addedCount, result.backup);
          return "added";
        } catch (JagexCdpAutomation.RateLimitedException exception) {
          handleRateLimit(account, exception);
          attempt--;
          continue;
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

    private ProxyConfig activeProxy() {
      return proxyIndex >= 0 && proxyIndex < proxies.size() ? proxies.get(proxyIndex) : ProxyConfig.none();
    }

    private void handleRateLimit(AccountRow account, JagexCdpAutomation.RateLimitedException exception) {
      if (rotateProxy()) {
        log.accept("row " + account.index + " Jagex rate limited the current proxy; switching to next proxy "
            + (proxyIndex + 1) + "/" + proxies.size());
        return;
      }
      long cooldownMs = Math.max(60_000L, config.rateLimitCooldownMs);
      String subject = proxies.isEmpty()
          ? "the current connection"
          : (proxies.size() == 1 ? "the current proxy" : "all configured proxies");
      log.accept("row " + account.index + " Jagex rate limited " + subject + "; cooling down for "
          + formatDuration(cooldownMs) + " before retrying");
      log.accept("row " + account.index + " rate-limit detail: " + shortReason(exception.getMessage()));
      control.sleep(cooldownMs);
    }

    private boolean rotateProxy() {
      if (proxies.size() <= 1) {
        return false;
      }
      if (proxyIndex + 1 >= proxies.size()) {
        proxyIndex = 0;
        return false;
      }
      proxyIndex++;
      return true;
    }

    private DreamBotAccountStore.AddResult verifyStoreResult(DreamBotAccountStore.AddResult result,
        String action) throws Exception {
      if (expectedDbCount >= 0 && result.beforeCount != expectedDbCount) {
        throw new IllegalStateException("accounts.db changed outside the importer before " + action
            + ". Close DreamBot and rerun so it cannot overwrite the account store.");
      }
      DreamBotAccountStore.Info persisted = DreamBotAccountStore.info(config.db);
      if (persisted.count != result.afterCount) {
        throw new IllegalStateException("accounts.db verification failed after " + action
            + ". Close DreamBot and rerun so it cannot overwrite the account store.");
      }
      expectedDbCount = persisted.count;
      return result;
    }

    private void verifyFinalDbCount() throws Exception {
      DreamBotAccountStore.Info persisted = DreamBotAccountStore.info(config.db);
      if (expectedDbCount >= 0 && persisted.count != expectedDbCount) {
        throw new IllegalStateException("accounts.db final verification failed. Close DreamBot and rerun so it "
            + "cannot overwrite the account store.");
      }
    }

    private String browserSummary(Config config) {
      String visibility = config.isHeadless()
          ? ("system".equalsIgnoreCase(config.browserEngine) ? "headless" : "minimized/internal")
          : "visible";
      if ("system".equalsIgnoreCase(config.browserEngine)) {
        String browser = config.browserPath == null || config.browserPath.isBlank()
            ? "auto-located Chrome/Chromium/Edge"
            : config.browserPath;
        return "Browser: " + browser + " (" + visibility + ")" + proxySummary();
      }
      Path jcefDir = config.jcefDir == null ? JcefBrowserLauncher.defaultInstallDir() : config.jcefDir;
      return "Browser: embedded JCEF (" + visibility + "), runtime cache " + jcefDir.toAbsolutePath()
          + proxySummary();
    }

    private String proxySummary() {
      return proxies.isEmpty() ? "" : ", starting on proxy 1/" + proxies.size();
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

    private String formatDuration(long millis) {
      long totalMinutes = Math.max(1L, TimeUnit.MILLISECONDS.toMinutes(millis));
      long hours = totalMinutes / 60L;
      long minutes = totalMinutes % 60L;
      if (hours == 0L) {
        return totalMinutes + "m";
      }
      if (minutes == 0L) {
        return hours + "h";
      }
      return hours + "h " + minutes + "m";
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
        row.put("detail", truncate(sanitizeDiagnostic(account, detail), 700));
      }
      Files.writeString(config.ledger, Json.stringify(row) + "\n", StandardCharsets.UTF_8,
          java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
      chmod600(config.ledger);
    }

    private void recordRun(String status, String detail) throws IOException {
      LinkedHashMap<String, Object> row = new LinkedHashMap<>();
      row.put("at", Instant.now().toString());
      row.put("scope", "run");
      row.put("status", status);
      if (detail != null && !detail.trim().isEmpty()) {
        row.put("detail", truncate(sanitizeDiagnostic(detail), 700));
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
    String browserEngine = "jcef";
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
    List<ProxyConfig> proxies = new ArrayList<>(ProxyConfig.listFromEnv());
    long rateLimitCooldownMs = DEFAULT_RATE_LIMIT_COOLDOWN_MS;

    boolean isHeadless() {
      return headless == null ? !"system".equalsIgnoreCase(browserEngine) : headless;
    }

    static Config parse(List<String> argv) {
      Config config = new Config();
      Path proxyFile = null;
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
            config.browserEngine = requireValue(argv, ++i, arg);
            break;
          case "--browser":
            config.browserPath = requireValue(argv, ++i, arg);
            break;
          case "--user-data-dir":
            config.userDataDir = Paths.get(requireValue(argv, ++i, arg));
            break;
          case "--system-browser":
            config.browserEngine = "system";
            break;
          case "--embedded-browser":
            config.browserEngine = "jcef";
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
          case "--rate-limit-cooldown-minutes":
            config.rateLimitCooldownMs = TimeUnit.MINUTES.toMillis(
                Math.max(1L, Long.parseLong(requireValue(argv, ++i, arg))));
            break;
          case "--proxy-file":
            proxyFile = Paths.get(requireValue(argv, ++i, arg));
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
      if (proxyFile != null) {
        try {
          config.proxies = readProxyFile(proxyFile);
        } catch (IOException exception) {
          throw new IllegalArgumentException("could not read proxy file: " + proxyFile);
        }
      }
      if (!config.stdin && config.input == null) {
        throw new IllegalArgumentException("--input or --stdin is required");
      }
      return config;
    }
  }

  private static void showAccountsDbBrowser(Path db) {
    try {
      List<Map<String, Object>> rows = DreamBotAccountStore.read(db);
      JFrame frame = new JFrame("accounts.db browser");
      frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

      JLabel summary = new JLabel(db.toAbsolutePath().normalize().toString());
      JTable table = new JTable(accountsDbTableModel(rows));
      table.setAutoCreateRowSorter(true);
      table.setFillsViewportHeight(true);
      table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
      setColumnWidths(table);

      JPanel content = new JPanel(new BorderLayout(8, 8));
      content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
      content.add(summary, BorderLayout.NORTH);
      content.add(new JScrollPane(table), BorderLayout.CENTER);

      frame.setContentPane(content);
      frame.setSize(1180, 640);
      frame.setLocationRelativeTo(null);
      frame.setVisible(true);
    } catch (Exception exception) {
      throw new IllegalStateException("could not read accounts.db: " + exception.getMessage(), exception);
    }
  }

  private static DefaultTableModel accountsDbTableModel(List<Map<String, Object>> rows) {
    List<String> columns = accountsDbColumns(rows);
    Object[][] data = new Object[rows.size()][columns.size()];
    for (int i = 0; i < rows.size(); i++) {
      Map<String, Object> row = rows.get(i);
      data[i][0] = i + 1;
      for (int column = 1; column < columns.size(); column++) {
        data[i][column] = dbCellValue(row.get(columns.get(column)));
      }
    }
    return new DefaultTableModel(data, columns.toArray(new String[0])) {
      @Override
      public boolean isCellEditable(int row, int column) {
        return false;
      }

      @Override
      public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == 0 ? Integer.class : String.class;
      }
    };
  }

  private static List<String> accountsDbColumns(List<Map<String, Object>> rows) {
    ArrayList<String> columns = new ArrayList<>();
    columns.add("#");
    for (String key : List.of(
        "nickname", "username", "password", "pin", "totp", "ssoEmail", "ssoPassword",
        "characterId", "sessionId", "accessToken", "refreshToken", "expiresAt", "banned")) {
      if (rows.stream().anyMatch(row -> row.containsKey(key))) {
        columns.add(key);
      }
    }
    ArrayList<String> extra = new ArrayList<>();
    for (Map<String, Object> row : rows) {
      for (String key : row.keySet()) {
        if (!columns.contains(key) && !extra.contains(key)) {
          extra.add(key);
        }
      }
    }
    Collections.sort(extra);
    columns.addAll(extra);
    return columns;
  }

  private static String dbCellValue(Object value) {
    if (value == null) {
      return "";
    }
    if (value instanceof String || value instanceof Number || value instanceof Boolean) {
      return String.valueOf(value);
    }
    return Json.stringify(value);
  }

  private static void setColumnWidths(JTable table) {
    for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
      String name = table.getColumnName(i);
      int width = "#".equals(name) ? 48 : 180;
      if (name.toLowerCase(Locale.ROOT).contains("token") || name.toLowerCase(Locale.ROOT).contains("session")) {
        width = 360;
      } else if (name.toLowerCase(Locale.ROOT).contains("password")
          || name.toLowerCase(Locale.ROOT).contains("email")
          || name.toLowerCase(Locale.ROOT).contains("username")
          || name.toLowerCase(Locale.ROOT).contains("nickname")) {
        width = 240;
      }
      table.getColumnModel().getColumn(i).setPreferredWidth(width);
    }
  }

  private static final class Gui {
    private final JTextField input = new JTextField();
    private final JTextField db = new JTextField();
    private final JTextField proxyFile = new JTextField();
    private final JButton viewDb = new JButton("View DB");
    private final JCheckBox headless = new JCheckBox("Minimized/internal browser", true);
    private final JProgressBar progress = new JProgressBar();
    private final JLabel status = new JLabel("Idle");
    private final JTextArea log = new JTextArea(16, 82);
    private final JButton start = new JButton("Start");
    private final JButton pause = new JButton("Pause");
    private final JButton stop = new JButton("Stop");
    private SwingWorker<Integer, String> worker;
    private GuiRunControl runControl;

    void show() {
      JFrame frame = new JFrame("Pernasua DreamBot Jagex Bulk Importer");
      frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      frame.setLayout(new BorderLayout(8, 8));

      JPanel form = new JPanel(new GridBagLayout());
      addRow(form, 0, "Accounts file", input, chooserButton(input, false));
      addDbRow(form, 1);
      addRow(form, 2, "Proxy file", proxyFile, chooserButton(proxyFile, false));
      autoDetectDbOnce();
      viewDb.addActionListener(event -> showSelectedAccountsDb());

      JPanel buttons = new JPanel();
      start.addActionListener(event -> start());
      pause.addActionListener(event -> togglePause());
      stop.addActionListener(event -> stop());
      pause.setEnabled(false);
      stop.setEnabled(false);
      buttons.add(headless);
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
      return chooserButton(target, save, null);
    }

    private JButton chooserButton(JTextField target, boolean save, Runnable afterSelect) {
      JButton button = new JButton("Browse");
      button.addActionListener(event -> {
        JFileChooser chooser = new JFileChooser();
        int result = save ? chooser.showSaveDialog(null) : chooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
          target.setText(chooser.getSelectedFile().toString());
          if (afterSelect != null) {
            afterSelect.run();
          }
        }
      });
      return button;
    }

    private void addRow(JPanel panel, int y, String label, JTextField field, java.awt.Component action) {
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
      panel.add(action, c);
    }

    private void addDbRow(JPanel panel, int y) {
      JPanel actions = new JPanel();
      actions.add(chooserButton(db, false));
      actions.add(viewDb);
      addRow(panel, y, "accounts.db", db, actions);
    }

    private void autoDetectDbOnce() {
      if (!db.getText().trim().isEmpty()) {
        return;
      }
      Path detected = autoDetectAccountsDb();
      if (detected != null) {
        db.setText(detected.toString());
        status.setText("Auto-detected accounts.db");
      }
    }

    private Path selectedDbPath() {
      String path = db.getText().trim();
      return path.isEmpty() ? null : Paths.get(path);
    }

    private void showSelectedAccountsDb() {
      Path path = selectedDbPath();
      if (path == null) {
        status.setText("Select accounts.db first");
        return;
      }
      try {
        showAccountsDbBrowser(path);
      } catch (RuntimeException exception) {
        status.setText("Could not open accounts.db browser: " + sanitizeDiagnostic(exception.getMessage()));
      }
    }

    private void start() {
      if (worker != null && !worker.isDone()) {
        return;
      }
      Config config = new Config();
      config.input = input.getText().trim().isEmpty() ? null : Paths.get(input.getText().trim());
      config.db = db.getText().trim().isEmpty() ? null : Paths.get(db.getText().trim());
      config.headless = headless.isSelected();
      if (proxyFile.getText().trim().isEmpty()) {
        config.proxies = List.of();
      } else {
        try {
          config.proxies = readProxyFile(Paths.get(proxyFile.getText().trim()));
        } catch (IOException exception) {
          status.setText("Could not read proxy file");
          appendLog("Could not read proxy file: " + sanitizeDiagnostic(exception.getMessage()));
          return;
        }
      }

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
            String message = sanitizeDiagnostic(exception.getMessage());
            appendLog("Failed: " + message);
            status.setText("Failed: " + message);
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
      log.append(sanitizeDiagnostic(line) + "\n");
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

  private static Path autoDetectAccountsDb() {
    ArrayList<Path> candidates = new ArrayList<>();
    addAccountsDbCandidate(candidates, System.getenv("DREAMBOT_ACCOUNTS_DB"));
    addAccountsDbCandidate(candidates, System.getenv("DREAMBOT_DB"));

    String home = System.getProperty("user.home", "").trim();
    if (!home.isEmpty()) {
      addAccountsDbCandidate(candidates, Paths.get(home, "DreamBot", "BotData", "accounts.db"));
    }
    addAccountsDbCandidate(candidates, Paths.get("DreamBot", "BotData", "accounts.db"));
    addAccountsDbCandidate(candidates,
        Paths.get("..", "dreambot", "run", "shared-db-state", "DreamBot", "BotData", "accounts.db"));
    addAccountsDbCandidate(candidates,
        Paths.get("..", "dreambot", "data", "DreamBot", "BotData", "accounts.db"));

    String appData = System.getenv("APPDATA");
    if (appData != null && !appData.trim().isEmpty()) {
      addAccountsDbCandidate(candidates, Paths.get(appData, "DreamBot", "BotData", "accounts.db"));
    }
    String localAppData = System.getenv("LOCALAPPDATA");
    if (localAppData != null && !localAppData.trim().isEmpty()) {
      addAccountsDbCandidate(candidates, Paths.get(localAppData, "DreamBot", "BotData", "accounts.db"));
    }

    LinkedHashSet<Path> seen = new LinkedHashSet<>();
    for (Path candidate : candidates) {
      Path normalized = candidate.toAbsolutePath().normalize();
      if (seen.add(normalized) && isAutoDetectableAccountsDb(normalized)) {
        return normalized;
      }
    }
    return null;
  }

  private static void addAccountsDbCandidate(List<Path> candidates, String rawPath) {
    if (rawPath == null || rawPath.trim().isEmpty()) {
      return;
    }
    try {
      addAccountsDbCandidate(candidates, Paths.get(rawPath.trim()));
    } catch (RuntimeException ignored) {
      // Ignore invalid platform-specific path strings.
    }
  }

  private static void addAccountsDbCandidate(List<Path> candidates, Path path) {
    if (path != null) {
      candidates.add(path);
    }
  }

  private static boolean isAutoDetectableAccountsDb(Path path) {
    if (!Files.isRegularFile(path)) {
      return false;
    }
    String normalized = path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    return normalized.endsWith("/botdata/accounts.db");
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

  private static void requireArgCount(List<String> argv, int expected, String mode) {
    if (argv.size() < expected) {
      throw new IllegalArgumentException(mode + " requires a value");
    }
    if (argv.size() > expected) {
      int values = expected - 1;
      if (values == 0) {
        throw new IllegalArgumentException(mode + " does not accept additional arguments");
      }
      throw new IllegalArgumentException(mode + " accepts exactly " + values
          + (values == 1 ? " value" : " values"));
    }
  }

  private static Map<String, String> parseOptions(List<String> argv, Set<String> allowedKeys) {
    LinkedHashMap<String, String> options = new LinkedHashMap<>();
    for (int i = 0; i < argv.size(); i++) {
      String arg = argv.get(i);
      if (!arg.startsWith("--")) {
        throw new IllegalArgumentException("unknown argument: " + arg);
      }
      String key = arg.substring(2);
      if (!allowedKeys.contains(key)) {
        throw new IllegalArgumentException("unknown option: " + arg);
      }
      if (i + 1 >= argv.size() || argv.get(i + 1).startsWith("--")) {
        options.put(key, "true");
      } else {
        options.put(key, requireValue(argv, ++i, arg));
      }
    }
    return options;
  }

  private static List<ProxyConfig> proxyListFromOptions(Map<String, String> options) throws IOException {
    if (options.containsKey("proxy-file")) {
      return readProxyFile(Paths.get(options.get("proxy-file")));
    }
    return ProxyConfig.listFromEnv();
  }

  private static List<ProxyConfig> readProxyFile(Path file) throws IOException {
    if (!Files.isRegularFile(file)) {
      throw new IllegalArgumentException("proxy file does not exist: " + file);
    }
    return ProxyConfig.parseList(Files.readString(file, StandardCharsets.UTF_8));
  }

  private static ProxyConfig firstProxy(List<ProxyConfig> proxies) {
    return proxies == null || proxies.isEmpty() ? ProxyConfig.none() : proxies.get(0);
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

  private static String sanitizeDiagnostic(AccountRow account, String text) {
    if (account == null) {
      return sanitizeDiagnostic(text);
    }
    return DiagnosticSanitizer.sanitize(text, account.email, account.password, account.otpSecret);
  }

  private static String sanitizeDiagnostic(String text, String... values) {
    return DiagnosticSanitizer.sanitize(text, values);
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
