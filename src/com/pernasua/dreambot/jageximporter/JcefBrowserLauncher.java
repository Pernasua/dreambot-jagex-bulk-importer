package com.pernasua.dreambot.jageximporter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Frame;
import java.awt.Point;
import java.awt.Robot;
import java.awt.event.InputEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import me.friwi.jcefmaven.CefAppBuilder;
import me.friwi.jcefmaven.EnumProgress;
import me.friwi.jcefmaven.IProgressHandler;
import org.cef.CefApp;
import org.cef.CefClient;
import org.cef.CefSettings;
import org.cef.browser.CefBrowser;
import org.cef.browser.CefFrame;
import org.cef.handler.CefRequestHandlerAdapter;
import org.cef.handler.CefResourceRequestHandler;
import org.cef.handler.CefResourceRequestHandlerAdapter;
import org.cef.misc.BoolRef;
import org.cef.network.CefRequest;

final class JcefBrowserLauncher {
  private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(90);
  private static final Object INIT_LOCK = new Object();
  private static CefApp app;
  private static Path activeInstallDir;
  private static int activePort;

  private JcefBrowserLauncher() {
  }

  static BrowserSession launch(Path installDir, int requestedPort, boolean keepOpen, boolean headless,
      Consumer<String> log) throws Exception {
    Consumer<String> safeLog = DiagnosticSanitizer.consumer(log);
    requireDisplayIfLinux();
    int port = ensureApp(installDir, requestedPort, safeLog);
    CefClient client = app.createClient();
    ReferrerRegistry referrers = new ReferrerRegistry();
    client.addRequestHandler(new ReferrerRequestHandler(referrers, safeLog));
    CefBrowser browser = client.createBrowser("about:blank", false, false);
    JFrame frame = showBrowserWindow(browser, !headless);

    String endpoint = "http://127.0.0.1:" + port;
    waitForDevTools(endpoint);
    return new BrowserSession(BrowserEngine.JCEF, endpoint, port, headless, keepOpen,
        () -> closeBrowser(browser, client, frame, keepOpen),
        () -> revealBrowser(frame),
        () -> hideBrowser(frame),
        referrers::register,
        url -> loadUrl(browser, url),
        (x, y, label) -> nativeViewportClick(browser, frame, x, y, label, safeLog));
  }

  static Path defaultInstallDir() {
    return defaultRoot().resolve("jcef");
  }

  static Path defaultProfileDir(Path installDir) {
    Path parent = installDir.toAbsolutePath().getParent();
    if (parent == null) {
      parent = Paths.get(".");
    }
    return parent.resolve("profile");
  }

  private static int ensureApp(Path requestedInstallDir, int requestedPort, Consumer<String> log) throws Exception {
    synchronized (INIT_LOCK) {
      Path installDir = (requestedInstallDir == null ? defaultInstallDir() : requestedInstallDir)
          .toAbsolutePath().normalize();
      int port = requestedPort > 0 ? requestedPort : (activePort > 0 ? activePort : Ports.freePort());
      if (app != null) {
        if (!Objects.equals(activeInstallDir, installDir)) {
          throw new IllegalStateException("embedded JCEF is already initialized with " + activeInstallDir);
        }
        if (requestedPort > 0 && requestedPort != activePort) {
          throw new IllegalStateException("embedded JCEF is already initialized on DevTools port " + activePort);
        }
        return activePort;
      }

      Files.createDirectories(installDir);
      CefAppBuilder builder = new CefAppBuilder();
      builder.setInstallDir(installDir.toFile());
      builder.setProgressHandler(new ProgressLogger(log));
      builder.addJcefArgs(
          "--remote-debugging-address=127.0.0.1",
          "--remote-allow-origins=*",
          "--window-size=1280,900");
      if (isLinux()) {
        builder.addJcefArgs("--no-sandbox");
      }

      CefSettings settings = builder.getCefSettings();
      settings.windowless_rendering_enabled = false;
      settings.remote_debugging_port = port;
      settings.cache_path = "";
      settings.user_agent = defaultUserAgent();
      settings.log_file = defaultRoot().resolve("jcef.log").toString();
      settings.log_severity = CefSettings.LogSeverity.LOGSEVERITY_DISABLE;

      log.accept("starting embedded JCEF on DevTools port " + port);
      app = builder.build();
      activeInstallDir = installDir;
      activePort = port;
      return activePort;
    }
  }

  private static JFrame showBrowserWindow(CefBrowser browser, boolean visibleOnScreen) throws Exception {
    final JFrame[] frame = new JFrame[1];
    SwingUtilities.invokeAndWait(() -> {
      JFrame window = new JFrame("DreamBot Jagex Importer Browser");
      window.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
      window.setLayout(new BorderLayout());
      window.add(browser.getUIComponent(), BorderLayout.CENTER);
      window.setSize(1280, 900);
      if (visibleOnScreen) {
        window.setLocationRelativeTo(null);
      } else {
        window.setLocation(0, 0);
      }
      window.setVisible(true);
      if (!visibleOnScreen) {
        window.setState(JFrame.ICONIFIED);
      }
      browser.createImmediately();
      frame[0] = window;
    });
    return frame[0];
  }

  private static void waitForDevTools(String endpoint) throws Exception {
    long deadline = System.currentTimeMillis() + STARTUP_TIMEOUT.toMillis();
    while (System.currentTimeMillis() < deadline) {
      try {
        if (!CdpClient.targets(endpoint).isEmpty()) {
          return;
        }
      } catch (IOException ignored) {
        // CEF is still starting.
      }
      Thread.sleep(300);
    }
    throw new IllegalStateException("timed out waiting for embedded JCEF DevTools at " + endpoint);
  }

  private static void closeBrowser(CefBrowser browser, CefClient client, JFrame frame, boolean keepOpen) throws Exception {
    if (keepOpen) {
      return;
    }
    try {
      browser.close(true);
    } finally {
      client.dispose();
      if (frame != null) {
        SwingUtilities.invokeAndWait(frame::dispose);
      }
    }
  }

  private static void revealBrowser(JFrame frame) {
    if (frame == null) {
      return;
    }
    SwingUtilities.invokeLater(() -> {
      frame.setState(JFrame.NORMAL);
      frame.setLocationRelativeTo(null);
      frame.setVisible(true);
      frame.toFront();
      frame.requestFocus();
    });
  }

  private static void hideBrowser(JFrame frame) {
    if (frame == null) {
      return;
    }
    SwingUtilities.invokeLater(() -> {
      frame.setState(JFrame.ICONIFIED);
    });
  }

  private static void loadUrl(CefBrowser browser, String url) {
    try {
      SwingUtilities.invokeAndWait(() -> browser.loadURL(url));
    } catch (Exception exception) {
      throw new IllegalStateException("could not navigate embedded JCEF browser", exception);
    }
  }

  private static String nativeViewportClick(CefBrowser browser, JFrame frame, double viewportX,
      double viewportY, String label, Consumer<String> log) {
    if (browser == null || frame == null) {
      return "";
    }
    int[] click = new int[2];
    int[] componentSize = new int[2];
    try {
      SwingUtilities.invokeAndWait(() -> {
        Component component = browser.getUIComponent();
        if ((frame.getExtendedState() & Frame.ICONIFIED) != 0) {
          frame.setExtendedState(frame.getExtendedState() & ~Frame.ICONIFIED);
        }
        frame.setVisible(true);
        frame.toFront();
        frame.requestFocus();
        component.requestFocus();
        component.requestFocusInWindow();
        Point origin = component.getLocationOnScreen();
        int width = Math.max(1, component.getWidth());
        int height = Math.max(1, component.getHeight());
        int localX = clamp((int) Math.round(viewportX), 1, width - 2);
        int localY = clamp((int) Math.round(viewportY), 1, height - 2);
        click[0] = origin.x + localX;
        click[1] = origin.y + localY;
        componentSize[0] = width;
        componentSize[1] = height;
      });
      Thread.sleep(120L);
      Robot robot = new Robot();
      robot.setAutoDelay(35);
      robot.mouseMove(click[0], click[1]);
      robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
      robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
      robot.waitForIdle();
      return "JCEF component " + safeLabel(label)
          + " viewport=" + Math.round(viewportX) + "," + Math.round(viewportY)
          + " size=" + componentSize[0] + "x" + componentSize[1];
    } catch (Exception exception) {
      log.accept("embedded JCEF native click failed: " + brief(exception.getMessage()));
      return "";
    }
  }

  private static int clamp(int value, int min, int max) {
    if (max < min) {
      return min;
    }
    return Math.max(min, Math.min(max, value));
  }

  private static String safeLabel(String label) {
    String text = label == null || label.isBlank() ? "browser click" : label.trim();
    return text.length() > 80 ? text.substring(0, 80) : text;
  }

  private static String brief(String value) {
    String text = DiagnosticSanitizer.sanitize(value == null ? "" : value).replaceAll("\\s+", " ").trim();
    return text.length() > 220 ? text.substring(0, 220) : text;
  }

  private static Path defaultRoot() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.contains("win")) {
      String localAppData = System.getenv("LOCALAPPDATA");
      if (localAppData != null && !localAppData.trim().isEmpty()) {
        return Paths.get(localAppData, "DreamBotJagexBulkImporter");
      }
    }
    String xdg = System.getenv("XDG_CACHE_HOME");
    if (xdg != null && !xdg.trim().isEmpty()) {
      return Paths.get(xdg, "dreambot-jagex-bulk-importer");
    }
    return Paths.get(System.getProperty("user.home", "."), ".cache", "dreambot-jagex-bulk-importer");
  }

  private static boolean isLinux() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
  }

  private static String defaultUserAgent() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.contains("win")) {
      return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          + "(KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36";
    }
    if (os.contains("mac")) {
      return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
          + "(KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36";
    }
    return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36";
  }

  private static void requireDisplayIfLinux() {
    if (!isLinux()) {
      return;
    }
    String display = System.getenv("DISPLAY");
    if (display == null || display.trim().isEmpty()) {
      throw new IllegalStateException("embedded JCEF requires a Linux display server; run under a desktop session or xvfb-run");
    }
  }

  private static final class ProgressLogger implements IProgressHandler {
    private final Consumer<String> log;
    private EnumProgress lastStage;
    private int lastBucket = -1;

    ProgressLogger(Consumer<String> log) {
      this.log = log == null ? ignored -> { } : log;
    }

    @Override
    public void handleProgress(EnumProgress stage, float percent) {
      int bucket = percent < 0 ? -1 : Math.min(100, Math.max(0, ((int) percent / 25) * 25));
      if (stage == lastStage && bucket == lastBucket) {
        return;
      }
      lastStage = stage;
      lastBucket = bucket;
      String name = stage.name().toLowerCase(Locale.ROOT);
      log.accept(bucket >= 0 ? "embedded JCEF " + name + " " + bucket + "%" : "embedded JCEF " + name);
    }
  }

  private static final class ReferrerRegistry {
    private final ConcurrentMap<String, String> referrers = new ConcurrentHashMap<>();

    void register(JagexOAuthClient.AuthRequest request) {
      if (request == null || request.url.isEmpty() || request.referrer.isEmpty()) {
        return;
      }
      referrers.put(request.url, request.referrer);
    }

    String lookup(String url) {
      return url == null ? null : referrers.get(url);
    }
  }

  private static final class ReferrerRequestHandler extends CefRequestHandlerAdapter {
    private final ReferrerRegistry referrers;
    private final Consumer<String> log;

    ReferrerRequestHandler(ReferrerRegistry referrers, Consumer<String> log) {
      this.referrers = referrers;
      this.log = log == null ? ignored -> { } : log;
    }

    @Override
    public CefResourceRequestHandler getResourceRequestHandler(CefBrowser browser, CefFrame frame,
        CefRequest request, boolean isNavigation, boolean isDownload, String requestInitiator,
        BoolRef disableDefaultHandling) {
      return new ReferrerResourceRequestHandler(referrers, log);
    }
  }

  private static final class ReferrerResourceRequestHandler extends CefResourceRequestHandlerAdapter {
    private final ReferrerRegistry referrers;
    private final Consumer<String> log;

    ReferrerResourceRequestHandler(ReferrerRegistry referrers, Consumer<String> log) {
      this.referrers = referrers;
      this.log = log == null ? ignored -> { } : log;
    }

    @Override
    public boolean onBeforeResourceLoad(CefBrowser browser, CefFrame frame, CefRequest request) {
      String referrer = referrers.lookup(request.getURL());
      if (referrer != null && !referrer.isEmpty()) {
        request.setReferrer(referrer, CefRequest.ReferrerPolicy.REFERRER_POLICY_DEFAULT);
        log.accept("embedded JCEF applied launcher OAuth referrer");
      }
      return false;
    }
  }
}
