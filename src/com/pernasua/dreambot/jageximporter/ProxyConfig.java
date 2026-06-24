package com.pernasua.dreambot.jageximporter;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class ProxyConfig {
  private static final ProxyConfig NONE = new ProxyConfig("", "", "");

  private final String server;
  private final String username;
  private final String password;

  private ProxyConfig(String server, String username, String password) {
    this.server = clean(server);
    this.username = clean(username);
    this.password = clean(password);
  }

  static ProxyConfig none() {
    return NONE;
  }

  static ProxyConfig fromEnv() {
    return of(
        System.getenv("CLOAK_PROXY_SERVER"),
        System.getenv("CLOAK_PROXY_USER"),
        System.getenv("CLOAK_PROXY_PASS"));
  }

  static List<ProxyConfig> listFromEnv() {
    ProxyConfig proxy = fromEnv();
    return proxy.enabled() ? List.of(proxy) : List.of();
  }

  static List<ProxyConfig> parseList(String raw) {
    ArrayList<ProxyConfig> proxies = new ArrayList<>();
    for (String line : String.valueOf(raw == null ? "" : raw).split("\\R")) {
      String trimmed = line.trim();
      if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        continue;
      }
      proxies.add(fromLine(trimmed));
    }
    return proxies;
  }

  static ProxyConfig fromLine(String line) {
    String trimmed = clean(line);
    if (trimmed.isEmpty()) {
      return NONE;
    }
    String[] parts = trimmed.split("\\|", -1);
    if (parts.length == 1) {
      return of(parts[0], "", "");
    }
    if (parts.length == 2) {
      return of(parts[0], parts[1], "");
    }
    return of(parts[0], parts[1], parts[2]);
  }

  static ProxyConfig of(String server, String username, String password) {
    if (clean(server).isEmpty()) {
      return NONE;
    }
    return new ProxyConfig(server, username, password);
  }

  boolean enabled() {
    return !server.isEmpty();
  }

  String server() {
    return server;
  }

  boolean isSocks() {
    return enabled() && parsed().scheme.startsWith("socks");
  }

  boolean hasCredentials() {
    return !username().isEmpty();
  }

  String username() {
    if (!username.isEmpty()) {
      return username;
    }
    String userInfo = parsed().rawUserInfo;
    if (userInfo == null || userInfo.isEmpty()) {
      return "";
    }
    int separator = userInfo.indexOf(':');
    return decode(separator >= 0 ? userInfo.substring(0, separator) : userInfo);
  }

  String password() {
    if (!password.isEmpty()) {
      return password;
    }
    String userInfo = parsed().rawUserInfo;
    if (userInfo == null || userInfo.isEmpty()) {
      return "";
    }
    int separator = userInfo.indexOf(':');
    return separator >= 0 ? decode(userInfo.substring(separator + 1)) : "";
  }

  URI uri() {
    ParsedProxy parsed = parsed();
    return URI.create(parsed.scheme + "://" + parsed.host + ":" + parsed.port);
  }

  String chromiumProxyArg() {
    if (!enabled()) {
      return "";
    }
    ParsedProxy parsed = parsed();
    String credentials = "";
    if (hasCredentials()) {
      credentials = encode(username()) + ":" + encode(password()) + "@";
    }
    return parsed.scheme + "://" + credentials + parsed.host + ":" + parsed.port;
  }

  String label() {
    if (!enabled()) {
      return "none";
    }
    ParsedProxy parsed = parsed();
    return parsed.scheme + "://" + parsed.host + ":" + parsed.port;
  }

  String signature() {
    return server + "\n" + username + "\n" + password;
  }

  private ParsedProxy parsed() {
    if (!enabled()) {
      throw new IllegalStateException("Proxy is not configured");
    }
    String raw = server;
    if (!raw.contains("://")) {
      raw = "http://" + raw;
    }
    URI uri;
    try {
      uri = URI.create(raw);
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException("Proxy server must be host:port or scheme://host:port");
    }
    String scheme = clean(uri.getScheme()).toLowerCase(Locale.ROOT);
    if (scheme.isEmpty()) {
      scheme = "http";
    }
    String host = clean(uri.getHost());
    int port = uri.getPort();
    if (host.isEmpty() || port <= 0) {
      throw new IllegalArgumentException("Proxy server must be host:port or scheme://host:port");
    }
    return new ParsedProxy(scheme, host, port, uri.getRawUserInfo());
  }

  private static String clean(String value) {
    return value == null ? "" : value.trim();
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static String decode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  private static final class ParsedProxy {
    final String scheme;
    final String host;
    final int port;
    final String rawUserInfo;

    ParsedProxy(String scheme, String host, int port, String rawUserInfo) {
      this.scheme = scheme;
      this.host = host;
      this.port = port;
      this.rawUserInfo = rawUserInfo;
    }
  }
}
