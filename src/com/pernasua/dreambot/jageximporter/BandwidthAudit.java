package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class BandwidthAudit {
  private static final Object LOCK = new Object();
  private static final Map<String, Record> ACTIVE_BROWSER = new LinkedHashMap<>();
  private static final List<Record> COMPLETED = new ArrayList<>();

  private BandwidthAudit() {
  }

  static void reset() {
    synchronized (LOCK) {
      ACTIVE_BROWSER.clear();
      COMPLETED.clear();
    }
  }

  static void browserRequest(String requestId, String method, String url, Map<String, Object> headers,
      String resourceType, String postData) {
    synchronized (LOCK) {
      Record record = ACTIVE_BROWSER.computeIfAbsent(requestId, ignored -> new Record());
      record.requestId = requestId;
      record.method = safe(method, "GET");
      record.url = safe(url, "");
      record.host = host(url);
      record.type = safe(resourceType, "other").toLowerCase(Locale.ROOT);
      record.source = "browser";
      record.requestHeaderBytes = estimateRequestHeaderBytes(record.method, record.url, headers);
      record.requestBodyBytes = postData == null ? 0L : postData.getBytes(StandardCharsets.UTF_8).length;
    }
  }

  static void browserResponse(String requestId, int status, Map<String, Object> headers) {
    synchronized (LOCK) {
      Record record = ACTIVE_BROWSER.computeIfAbsent(requestId, ignored -> new Record());
      record.requestId = requestId;
      record.status = status;
      record.responseHeaderBytes = estimateResponseHeaderBytes(status, headers);
    }
  }

  static void browserFinished(String requestId, long encodedDataLength, boolean failed) {
    synchronized (LOCK) {
      Record record = ACTIVE_BROWSER.remove(requestId);
      if (record == null) {
        record = new Record();
        record.requestId = requestId;
        record.source = "browser";
      }
      record.failed = failed;
      record.encodedDataLength = Math.max(0L, encodedDataLength);
      record.totalBytes = record.requestHeaderBytes + record.requestBodyBytes
          + record.responseHeaderBytes + record.encodedDataLength;
      COMPLETED.add(record);
    }
  }

  static void httpExchange(String type, HttpRequest request, HttpResponse<String> response) {
    Record record = new Record();
    record.source = "api";
    record.type = safe(type, "http").toLowerCase(Locale.ROOT);
    record.method = safe(request.method(), "GET");
    record.url = request.uri().toString();
    record.host = host(record.url);
    record.status = response.statusCode();
    record.requestHeaderBytes = estimateRequestHeaderBytes(record.method, record.url, flattenHeaders(request.headers().map()));
    long requestBodyBytes = request.bodyPublisher().map(HttpRequest.BodyPublisher::contentLength).orElse(0L);
    record.requestBodyBytes = Math.max(0L, requestBodyBytes);
    record.responseHeaderBytes = estimateResponseHeaderBytes(record.status, flattenHeaders(response.headers().map()));
    String body = response.body();
    record.encodedDataLength = body == null ? 0L : body.getBytes(StandardCharsets.UTF_8).length;
    record.totalBytes = record.requestHeaderBytes + record.requestBodyBytes
        + record.responseHeaderBytes + record.encodedDataLength;
    synchronized (LOCK) {
      COMPLETED.add(record);
    }
  }

  static LinkedHashMap<String, Object> summary() {
    ArrayList<Record> records;
    synchronized (LOCK) {
      records = new ArrayList<>(COMPLETED);
      records.addAll(ACTIVE_BROWSER.values());
    }
    LinkedHashMap<String, Long> byHost = new LinkedHashMap<>();
    LinkedHashMap<String, Long> byType = new LinkedHashMap<>();
    LinkedHashMap<String, Long> bySource = new LinkedHashMap<>();
    ArrayList<LinkedHashMap<String, Object>> topRequests = new ArrayList<>();
    long totalBytes = 0L;
    for (Record record : records) {
      long bytes = record.totalBytes();
      totalBytes += bytes;
      if (!record.host.isEmpty()) {
        byHost.put(record.host, byHost.getOrDefault(record.host, 0L) + bytes);
      }
      byType.put(record.type, byType.getOrDefault(record.type, 0L) + bytes);
      bySource.put(record.source, bySource.getOrDefault(record.source, 0L) + bytes);
      LinkedHashMap<String, Object> row = new LinkedHashMap<>();
      row.put("source", record.source);
      row.put("method", record.method);
      row.put("host", record.host);
      row.put("type", record.type);
      row.put("status", record.status);
      row.put("bytes", bytes);
      row.put("url", record.url);
      topRequests.add(row);
    }
    topRequests.sort((left, right) -> Long.compare(
        ((Number) right.get("bytes")).longValue(),
        ((Number) left.get("bytes")).longValue()));
    LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
    payload.put("kind", "importer-bandwidth");
    payload.put("request_count", records.size());
    payload.put("estimated_total_bytes", totalBytes);
    payload.put("by_host", sortTotals(byHost));
    payload.put("by_type", sortTotals(byType));
    payload.put("by_source", sortTotals(bySource));
    payload.put("top_requests", topRequests.subList(0, Math.min(40, topRequests.size())));
    return payload;
  }

  static void write(Path path) throws IOException {
    if (path == null) {
      return;
    }
    Files.createDirectories(path.toAbsolutePath().getParent());
    Files.writeString(path, Json.stringify(summary()) + "\n", StandardCharsets.UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
  }

  private static LinkedHashMap<String, Object> sortTotals(Map<String, Long> input) {
    ArrayList<Map.Entry<String, Long>> rows = new ArrayList<>(input.entrySet());
    rows.sort((left, right) -> Long.compare(right.getValue(), left.getValue()));
    LinkedHashMap<String, Object> out = new LinkedHashMap<>();
    for (Map.Entry<String, Long> row : rows) {
      out.put(row.getKey(), row.getValue());
    }
    return out;
  }

  private static String host(String url) {
    try {
      URI uri = URI.create(safe(url, ""));
      return uri.getHost() == null ? "" : uri.getHost();
    } catch (RuntimeException exception) {
      return "";
    }
  }

  private static String requestPath(String url) {
    try {
      URI uri = URI.create(safe(url, ""));
      String path = uri.getRawPath();
      String query = uri.getRawQuery();
      String out = (path == null || path.isEmpty()) ? "/" : path;
      if (query != null && !query.isEmpty()) {
        out += "?" + query;
      }
      return out;
    } catch (RuntimeException exception) {
      return "/";
    }
  }

  private static long estimateRequestHeaderBytes(String method, String url, Map<String, Object> headers) {
    long total = ("".equals(method) ? 0L : method.length()) + requestPath(url).length() + 12L;
    for (Map.Entry<String, Object> row : headers.entrySet()) {
      total += row.getKey().length() + String.valueOf(row.getValue()).length() + 4L;
    }
    return total + 2L;
  }

  private static long estimateResponseHeaderBytes(int status, Map<String, Object> headers) {
    long total = String.valueOf(status).length() + 12L;
    for (Map.Entry<String, Object> row : headers.entrySet()) {
      total += row.getKey().length() + String.valueOf(row.getValue()).length() + 4L;
    }
    return total + 2L;
  }

  private static Map<String, Object> flattenHeaders(Map<String, List<String>> headers) {
    LinkedHashMap<String, Object> out = new LinkedHashMap<>();
    for (Map.Entry<String, List<String>> row : headers.entrySet()) {
      out.put(row.getKey(), String.join(", ", row.getValue()));
    }
    return out;
  }

  private static String safe(String value, String defaultValue) {
    return value == null ? defaultValue : value;
  }

  private static final class Record {
    String requestId = "";
    String source = "browser";
    String method = "GET";
    String host = "";
    String type = "other";
    String url = "";
    int status = 0;
    boolean failed = false;
    long requestHeaderBytes = 0L;
    long requestBodyBytes = 0L;
    long responseHeaderBytes = 0L;
    long encodedDataLength = 0L;
    long totalBytes = 0L;

    long totalBytes() {
      if (totalBytes > 0L) {
        return totalBytes;
      }
      return requestHeaderBytes + requestBodyBytes + responseHeaderBytes + encodedDataLength;
    }
  }
}
