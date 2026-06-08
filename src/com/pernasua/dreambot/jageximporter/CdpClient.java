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

  private CdpClient(WebSocket socket) {
    this.socket = socket;
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
    String fallback = "";
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
      if (fallback.isEmpty()) {
        fallback = target.webSocketUrl;
      }
    }
    if (!fallback.isEmpty()) {
      return fallback;
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
      throw new IllegalStateException("CDP evaluation failed: " + Json.stringify(result.get("exceptionDetails")));
    }
    return Json.asObject(result.get("result")).get("value");
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
    synchronized (events) {
      events.add(message);
      if (events.size() > 500) {
        events.remove(0);
      }
      events.notifyAll();
    }
  }

  @Override
  public void close() {
    socket.sendClose(WebSocket.NORMAL_CLOSURE, "done").join();
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
