package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

final class CdpClient implements AutoCloseable {
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(8);
  private static final Duration CDP_TIMEOUT = Duration.ofSeconds(25);

  private final AtomicInteger nextId = new AtomicInteger(1);
  private final Map<Integer, CompletableFuture<Map<String, Object>>> pending = new ConcurrentHashMap<>();
  private final List<Map<String, Object>> events = new ArrayList<>();
  private final WebSocket socket;
  private final StringBuilder partialText = new StringBuilder();
  private final String sessionKey;

  private CdpClient(WebSocket socket) {
    this.socket = socket;
    this.sessionKey = Integer.toHexString(System.identityHashCode(socket));
  }

  static List<Target> targets(String baseUrl) throws IOException, InterruptedException {
    String clean = baseUrl.replaceAll("/+$", "");
    HttpRequest request = HttpRequest.newBuilder(URI.create(clean + "/json/list"))
        .timeout(HTTP_TIMEOUT)
        .GET()
        .build();
    String body = HttpClient.newHttpClient()
        .send(request, HttpResponse.BodyHandlers.ofString())
        .body();
    List<Target> targets = new ArrayList<>();
    for (Object item : Json.asList(Json.parse(body))) {
      Map<String, Object> row = Json.asObject(item);
      targets.add(new Target(
          Json.string(row.get("id")),
          Json.string(row.get("type")),
          Json.string(row.get("title")),
          Json.string(row.get("url")),
          Json.string(row.get("webSocketDebuggerUrl"))));
    }
    return targets;
  }

  static String newPage(String baseUrl, String url) throws IOException, InterruptedException {
    String clean = baseUrl.replaceAll("/+$", "");
    String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8);
    HttpRequest request = HttpRequest.newBuilder(URI.create(clean + "/json/new?" + encoded))
        .timeout(HTTP_TIMEOUT)
        .PUT(HttpRequest.BodyPublishers.noBody())
        .build();
    String body = HttpClient.newHttpClient()
        .send(request, HttpResponse.BodyHandlers.ofString())
        .body();
    return Json.string(Json.asObject(Json.parse(body)).get("webSocketDebuggerUrl"));
  }

  static String pageWebSocket(String baseUrl) throws IOException, InterruptedException {
    String firstPage = "";
    for (Target target : targets(baseUrl)) {
      if (target.webSocketUrl.isEmpty() || !"page".equalsIgnoreCase(target.type)) {
        continue;
      }
      String folded = (target.url + " " + target.title).toLowerCase(java.util.Locale.ROOT);
      if (folded.contains("account.jagex.com")
          || folded.contains("runescape.com")
          || folded.contains("localhost")
          || target.url.startsWith("jagex:")) {
        return target.webSocketUrl;
      }
      if (firstPage.isEmpty()) {
        firstPage = target.webSocketUrl;
      }
    }
    if (!firstPage.isEmpty()) {
      return firstPage;
    }
    throw new IllegalStateException("no browser page target was exposed by DevTools");
  }

  static CdpClient connect(String webSocketUrl) throws ExecutionException, InterruptedException {
    Listener listener = new Listener();
    WebSocket socket = HttpClient.newHttpClient()
        .newWebSocketBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .buildAsync(URI.create(webSocketUrl), listener)
        .get();
    CdpClient client = new CdpClient(socket);
    listener.attach(client);
    return client;
  }

  Map<String, Object> send(String method) {
    return send(method, new LinkedHashMap<>());
  }

  Map<String, Object> send(String method, Map<String, Object> params) {
    int id = nextId.getAndIncrement();
    LinkedHashMap<String, Object> message = new LinkedHashMap<>();
    message.put("id", id);
    message.put("method", method);
    message.put("params", params);
    CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
    pending.put(id, future);
    socket.sendText(Json.stringify(message), true).join();
    try {
      Map<String, Object> response = future.get(CDP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
      if (response.containsKey("error")) {
        throw new IllegalStateException(method + " failed: " + Json.stringify(response.get("error")));
      }
      return Json.asObject(response.get("result"));
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(method + " interrupted", exception);
    } catch (ExecutionException exception) {
      throw new IllegalStateException(method + " failed", exception.getCause());
    } catch (TimeoutException exception) {
      pending.remove(id);
      throw new IllegalStateException(method + " timed out", exception);
    }
  }

  Object evaluate(String expression) {
    return evaluate(expression, true);
  }

  Object evaluate(String expression, boolean returnByValue) {
    LinkedHashMap<String, Object> params = new LinkedHashMap<>();
    params.put("expression", expression);
    params.put("returnByValue", returnByValue);
    params.put("awaitPromise", true);
    params.put("userGesture", true);
    Map<String, Object> result = send("Runtime.evaluate", params);
    if (result.containsKey("exceptionDetails")) {
      throw new IllegalStateException("CDP evaluation failed: "
          + evaluationExceptionSummary(Json.asObject(result.get("exceptionDetails"))));
    }
    return Json.asObject(result.get("result")).get("value");
  }

  static String evaluationExceptionSummary(Map<String, Object> details) {
    Map<String, Object> exception = Json.asObject(details.get("exception"));
    String description = compact(Json.string(exception.get("description")));
    String className = compact(Json.string(exception.get("className")));
    String value = compact(Json.string(exception.get("value")));
    String text = compact(Json.string(details.get("text")));
    StringBuilder out = new StringBuilder();
    if (!description.isEmpty()) {
      out.append(description);
    } else if (!className.isEmpty() || !value.isEmpty()) {
      out.append(className.isEmpty() ? "exception" : className);
      if (!value.isEmpty()) {
        out.append(": ").append(value);
      }
    } else if (!text.isEmpty()) {
      out.append(text);
    } else {
      out.append("unknown exception");
    }
    String line = compact(Json.string(details.get("lineNumber")));
    String column = compact(Json.string(details.get("columnNumber")));
    if (!line.isEmpty() || !column.isEmpty()) {
      out.append(" at line ").append(line.isEmpty() ? "?" : line)
          .append(" column ").append(column.isEmpty() ? "?" : column);
    }
    Map<String, Object> stackTrace = Json.asObject(details.get("stackTrace"));
    List<Object> frames = Json.asList(stackTrace.get("callFrames"));
    if (!frames.isEmpty()) {
      Map<String, Object> frame = Json.asObject(frames.get(0));
      String function = compact(Json.string(frame.get("functionName")));
      String url = compact(Json.string(frame.get("url")));
      if (!function.isEmpty() || !url.isEmpty()) {
        out.append(" frame=");
        if (!function.isEmpty()) {
          out.append(function);
        }
        if (!url.isEmpty()) {
          if (!function.isEmpty()) {
            out.append("@");
          }
          out.append(url);
        }
      }
    }
    String summary = out.toString();
    return summary.length() <= 420 ? summary : summary.substring(0, 420);
  }

  private static String compact(String text) {
    return String.valueOf(text == null ? "" : text).replaceAll("\\s+", " ").trim();
  }

  void navigate(String url) {
    LinkedHashMap<String, Object> params = new LinkedHashMap<>();
    params.put("url", url);
    send("Page.navigate", params);
  }

  void setExtraHttpHeaders(Map<String, String> headers) {
    LinkedHashMap<String, Object> params = new LinkedHashMap<>();
    params.put("headers", new LinkedHashMap<>(headers));
    send("Network.setExtraHTTPHeaders", params);
  }

  List<String> observedUrls() {
    ArrayList<String> urls = new ArrayList<>();
    synchronized (events) {
      for (Map<String, Object> event : events) {
        String method = Json.string(event.get("method"));
        Map<String, Object> params = Json.asObject(event.get("params"));
        if ("Network.requestWillBeSent".equals(method)) {
          String url = Json.string(Json.asObject(params.get("request")).get("url"));
          if (!url.isEmpty()) {
            urls.add(url);
          }
        } else if ("Page.frameNavigated".equals(method)) {
          String url = Json.string(Json.asObject(params.get("frame")).get("url"));
          if (!url.isEmpty()) {
            urls.add(url);
          }
        } else if ("Page.navigatedWithinDocument".equals(method)) {
          String url = Json.string(params.get("url"));
          if (!url.isEmpty()) {
            urls.add(url);
          }
        }
      }
    }
    return urls;
  }

  private void receive(String text) {
    Object parsed = Json.parse(text);
    Map<String, Object> message = Json.asObject(parsed);
    Object idValue = message.get("id");
    if (idValue instanceof Number) {
      int id = ((Number) idValue).intValue();
      CompletableFuture<Map<String, Object>> future = pending.remove(id);
      if (future != null) {
        future.complete(message);
      }
      return;
    }
    recordBandwidthEvent(message);
    synchronized (events) {
      events.add(message);
      if (events.size() > 500) {
        events.remove(0);
      }
      events.notifyAll();
    }
  }

  private void recordBandwidthEvent(Map<String, Object> message) {
    String method = Json.string(message.get("method"));
    Map<String, Object> params = Json.asObject(message.get("params"));
    String requestKey = sessionKey + ":" + Json.string(params.get("requestId"));
    if ("Network.requestWillBeSent".equals(method)) {
      Map<String, Object> request = Json.asObject(params.get("request"));
      BandwidthAudit.browserRequest(
          requestKey,
          Json.string(request.get("method")),
          Json.string(request.get("url")),
          Json.asObject(request.get("headers")),
          Json.string(params.get("type")),
          Json.string(request.get("postData")));
      return;
    }
    if ("Network.responseReceived".equals(method)) {
      Map<String, Object> response = Json.asObject(params.get("response"));
      BandwidthAudit.browserResponse(
          requestKey,
          Json.number(response.get("status")).intValue(),
          Json.asObject(response.get("headers")));
      return;
    }
    if ("Network.loadingFinished".equals(method)) {
      BandwidthAudit.browserFinished(requestKey,
          Json.number(params.get("encodedDataLength")).longValue(), false);
      return;
    }
    if ("Network.loadingFailed".equals(method)) {
      BandwidthAudit.browserFinished(requestKey, 0L, true);
    }
  }

  @Override
  public void close() {
    try {
      socket.sendClose(WebSocket.NORMAL_CLOSURE, "done").join();
    } catch (RuntimeException exception) {
      String message = String.valueOf(exception.getMessage()).toLowerCase(java.util.Locale.ROOT);
      Throwable cause = exception.getCause();
      String causeMessage = cause == null ? "" : String.valueOf(cause.getMessage()).toLowerCase(java.util.Locale.ROOT);
      if (message.contains("output closed") || causeMessage.contains("output closed")) {
        return;
      }
      throw exception;
    }
  }

  static final class Target {
    final String id;
    final String type;
    final String title;
    final String url;
    final String webSocketUrl;

    Target(String id, String type, String title, String url, String webSocketUrl) {
      this.id = Objects.requireNonNullElse(id, "");
      this.type = Objects.requireNonNullElse(type, "");
      this.title = Objects.requireNonNullElse(title, "");
      this.url = Objects.requireNonNullElse(url, "");
      this.webSocketUrl = Objects.requireNonNullElse(webSocketUrl, "");
    }
  }

  private static final class Listener implements WebSocket.Listener {
    private CdpClient client;

    void attach(CdpClient client) {
      this.client = client;
    }

    @Override
    public void onOpen(WebSocket webSocket) {
      webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
      if (client != null) {
        synchronized (client.partialText) {
          client.partialText.append(data);
          if (last) {
            String message = client.partialText.toString();
            client.partialText.setLength(0);
            client.receive(message);
          }
        }
      }
      webSocket.request(1);
      return CompletableFuture.completedFuture(null);
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
      if (client != null) {
        for (CompletableFuture<Map<String, Object>> future : client.pending.values()) {
          future.completeExceptionally(new IOException("CDP websocket closed: " + statusCode + " " + reason));
        }
        client.pending.clear();
      }
      return CompletableFuture.completedFuture(null);
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
      if (client != null) {
        for (CompletableFuture<Map<String, Object>> future : client.pending.values()) {
          future.completeExceptionally(error);
        }
        client.pending.clear();
      }
    }
  }
}
