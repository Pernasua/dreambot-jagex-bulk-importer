package com.pernasua.dreambot.jageximporter;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

final class BrowserSession implements AutoCloseable {
  final String engine;
  final String endpoint;
  final int port;
  final boolean headless;
  final boolean keepOpen;

  private final AutoCloseable closeAction;
  private final Runnable revealAction;
  private final Runnable hideAction;
  private final Consumer<JagexOAuthClient.AuthRequest> authRequestAction;
  private final Consumer<String> navigateAction;
  private final NativeClickAction nativeClickAction;
  private final AtomicBoolean closed = new AtomicBoolean(false);

  BrowserSession(String engine, String endpoint, int port, boolean headless, boolean keepOpen,
      AutoCloseable closeAction, Runnable revealAction, Runnable hideAction,
      Consumer<JagexOAuthClient.AuthRequest> authRequestAction, Consumer<String> navigateAction,
      NativeClickAction nativeClickAction) {
    this.engine = String.valueOf(engine == null ? "" : engine).trim().toLowerCase(java.util.Locale.ROOT);
    this.endpoint = endpoint;
    this.port = port;
    this.headless = headless;
    this.keepOpen = keepOpen;
    this.closeAction = closeAction == null ? () -> { } : closeAction;
    this.revealAction = revealAction == null ? () -> { } : revealAction;
    this.hideAction = hideAction == null ? () -> { } : hideAction;
    this.authRequestAction = authRequestAction == null ? ignored -> { } : authRequestAction;
    this.navigateAction = navigateAction == null ? ignored -> { } : navigateAction;
    this.nativeClickAction = nativeClickAction == null ? (x, y, label) -> "" : nativeClickAction;
  }

  void reveal() {
    revealAction.run();
  }

  void hide() {
    hideAction.run();
  }

  void prepareAuthRequest(JagexOAuthClient.AuthRequest request) {
    authRequestAction.accept(request);
  }

  void navigate(String url) {
    navigateAction.accept(url);
  }

  String nativeClick(double viewportX, double viewportY, String label) {
    return nativeClickAction.click(viewportX, viewportY, label);
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    try {
      closeAction.close();
    } catch (RuntimeException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IllegalStateException("could not close browser session", exception);
    }
  }

  @FunctionalInterface
  interface NativeClickAction {
    String click(double viewportX, double viewportY, String label);
  }
}
