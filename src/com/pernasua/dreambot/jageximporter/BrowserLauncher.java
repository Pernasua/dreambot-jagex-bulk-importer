package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

final class BrowserLauncher {
  private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(35);

  private BrowserLauncher() {
  }

  static BrowserSession launch(String explicitBrowser, int requestedPort, boolean keepOpen, boolean headless) throws Exception {
    String browser = locateBrowser(explicitBrowser);
    int port = requestedPort > 0 ? requestedPort : Ports.freePort();
    Path profile = Files.createTempDirectory("dreambot-jagex-importer-browser-");

    ArrayList<String> command = new ArrayList<>();
    command.add(browser);
    if (headless) {
      command.add("--headless=new");
      command.add("--disable-gpu");
      command.add("--disable-dev-shm-usage");
    }
    command.add("--remote-debugging-address=127.0.0.1");
    command.add("--remote-debugging-port=" + port);
    command.add("--user-data-dir=" + profile.toAbsolutePath());
    command.add("--no-first-run");
    command.add("--no-default-browser-check");
    command.add("--disable-extensions");
    command.add("--disable-popup-blocking");
    command.add("--window-size=1280,900");
    if (isLinux()) {
      command.add("--no-sandbox");
    }
    command.add("about:blank");

    ProcessBuilder builder = new ProcessBuilder(command);
    builder.redirectErrorStream(true);
    Process process = builder.start();
    String endpoint = "http://127.0.0.1:" + port;
    long deadline = System.currentTimeMillis() + STARTUP_TIMEOUT.toMillis();
    while (System.currentTimeMillis() < deadline) {
      if (!process.isAlive()) {
        throw new IllegalStateException("browser exited before DevTools became available");
      }
      try {
        if (!CdpClient.targets(endpoint).isEmpty()) {
          return new BrowserSession(BrowserEngine.SYSTEM, endpoint, port, headless, keepOpen,
              () -> close(process, profile, keepOpen));
        }
      } catch (IOException ignored) {
        // Browser is still starting.
      }
      Thread.sleep(300);
    }
    process.destroyForcibly();
    deleteRecursive(profile);
    throw new IllegalStateException("timed out waiting for browser DevTools on port " + port);
  }

  static String locateBrowser(String explicitBrowser) {
    if (explicitBrowser != null && !explicitBrowser.trim().isEmpty()) {
      Path path = Path.of(explicitBrowser.trim());
      if (Files.isRegularFile(path) || Files.isExecutable(path)) {
        return path.toString();
      }
      throw new IllegalArgumentException("browser executable does not exist: " + explicitBrowser);
    }

    ArrayList<String> candidates = new ArrayList<>();
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.contains("win")) {
      String programFiles = System.getenv("PROGRAMFILES");
      String programFilesX86 = System.getenv("PROGRAMFILES(X86)");
      String localAppData = System.getenv("LOCALAPPDATA");
      addWindows(candidates, programFiles, "Microsoft/Edge/Application/msedge.exe");
      addWindows(candidates, programFilesX86, "Microsoft/Edge/Application/msedge.exe");
      addWindows(candidates, localAppData, "Microsoft/Edge/Application/msedge.exe");
      addWindows(candidates, programFiles, "Google/Chrome/Application/chrome.exe");
      addWindows(candidates, programFilesX86, "Google/Chrome/Application/chrome.exe");
      addWindows(candidates, localAppData, "Google/Chrome/Application/chrome.exe");
      candidates.add("msedge.exe");
      candidates.add("chrome.exe");
    } else if (os.contains("mac")) {
      candidates.add("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
      candidates.add("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
      candidates.add("/Applications/Chromium.app/Contents/MacOS/Chromium");
    } else {
      candidates.addAll(Arrays.asList(
          "google-chrome",
          "google-chrome-stable",
          "chromium",
          "chromium-browser",
          "microsoft-edge",
          "microsoft-edge-stable"));
    }

    for (String candidate : candidates) {
      if (candidate.contains("/") || candidate.contains("\\")) {
        if (Files.isRegularFile(Path.of(candidate)) || Files.isExecutable(Path.of(candidate))) {
          return candidate;
        }
      } else if (commandExists(candidate)) {
        return candidate;
      }
    }
    throw new IllegalStateException("could not find Chrome, Chromium, or Edge; pass --browser /path/to/browser");
  }

  private static void addWindows(List<String> candidates, String base, String suffix) {
    if (base != null && !base.trim().isEmpty()) {
      candidates.add(Path.of(base, suffix.split("/")).toString());
    }
  }

  private static boolean commandExists(String command) {
    try {
      Process process = isWindows()
          ? new ProcessBuilder("where", command).start()
          : new ProcessBuilder("sh", "-lc", "command -v " + shellQuote(command)).start();
      return process.waitFor() == 0;
    } catch (Exception ignored) {
      return false;
    }
  }

  private static String shellQuote(String value) {
    return "'" + value.replace("'", "'\\''") + "'";
  }

  private static boolean isLinux() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
  }

  private static boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
  }

  private static void deleteRecursive(Path path) {
    if (path == null || !Files.exists(path)) {
      return;
    }
    try {
      Files.walk(path)
          .sorted((left, right) -> right.compareTo(left))
          .forEach(item -> {
            try {
              Files.deleteIfExists(item);
            } catch (IOException ignored) {
              // Best-effort cleanup.
            }
          });
    } catch (IOException ignored) {
      // Best-effort cleanup.
    }
  }

  private static void close(Process process, Path profile, boolean keepOpen) {
    if (keepOpen) {
      return;
    }
    if (process.isAlive()) {
      process.destroy();
      try {
        if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
          process.destroyForcibly();
        }
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        process.destroyForcibly();
      }
    }
    deleteRecursive(profile);
  }
}
