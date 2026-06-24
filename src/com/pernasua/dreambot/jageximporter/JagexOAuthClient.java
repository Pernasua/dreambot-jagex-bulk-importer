package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class JagexOAuthClient {
  private static final String AUTH_URL = "https://account.jagex.com/oauth2/auth";
  private static final String TOKEN_URL = "https://account.jagex.com/oauth2/token";
  private static final String LAUNCHER_CLIENT_ID = "com_jagex_auth_desktop_launcher";
  private static final String LAUNCHER_REDIRECT_URI = "https://secure.runescape.com/m=weblogin/launcher-redirect";
  private static final String CONSENT_CLIENT_ID = "1fddee4e-b100-4f4e-b2b0-097f9088f9d2";
  private static final String GAME_SESSION_URL = "https://auth.runescape.com/game-session/v1/sessions";
  private static final String GAME_ACCOUNTS_URL =
      "https://auth.runescape.com/game-session/v1/accounts?fetchMembership=true";
  private static final String RS_PROFILE_URL = "https://secure.jagex.com/rs-profile/v1/profile";
  private static final String LAUNCHER_SCOPE =
      "openid offline gamesso.token.create user.profile.read user.entitlement.read "
          + "user.game.read user.sku.read user.voucher.redeem";
  private static final String CONSENT_SCOPE = "openid offline";
  private static final int GAME_SESSION_HTTP_RETRIES = 3;
  private static final Duration GAME_SESSION_CREATE_HTTP_TIMEOUT = Duration.ofSeconds(45);
  private static final Duration GAME_SESSION_LIST_HTTP_TIMEOUT = Duration.ofSeconds(30);
  private static final char[] ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
  private static final SecureRandom RANDOM = new SecureRandom();

  private final HttpClient http;
  private final java.util.function.Consumer<String> log;

  JagexOAuthClient() {
    this(message -> { });
  }

  JagexOAuthClient(java.util.function.Consumer<String> log) {
    this(log, ProxyConfig.fromEnv());
  }

  JagexOAuthClient(java.util.function.Consumer<String> log, ProxyConfig proxy) {
    this.log = DiagnosticSanitizer.consumer(log);
    HttpClient.Builder builder = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(20))
        .followRedirects(HttpClient.Redirect.NEVER);
    configureProxy(builder, proxy == null ? ProxyConfig.fromEnv() : proxy);
    this.http = builder.build();
  }

  AuthRequest launcherAuthRequest() {
    String state = randomAlnum(24);
    String codeVerifier = randomUrlToken(32);
    LinkedHashMap<String, String> params = new LinkedHashMap<>();
    params.put("auth_method", "");
    params.put("login_type", "");
    params.put("flow", "launcher");
    params.put("response_type", "code");
    params.put("client_id", LAUNCHER_CLIENT_ID);
    params.put("redirect_uri", LAUNCHER_REDIRECT_URI);
    params.put("code_challenge", codeChallenge(codeVerifier));
    params.put("code_challenge_method", "S256");
    params.put("prompt", "login");
    params.put("scope", LAUNCHER_SCOPE);
    params.put("state", state);
    return new AuthRequest(AUTH_URL + "?" + form(params), state, codeVerifier, launcherReferrer());
  }

  AuthRequest consentAuthRequest(Tokens tokens) {
    String state = randomAlnum(32);
    LinkedHashMap<String, String> params = new LinkedHashMap<>();
    params.put("id_token_hint", tokens.idToken);
    params.put("nonce", randomAlnum(48));
    params.put("prompt", "consent");
    params.put("redirect_uri", "http://localhost");
    params.put("response_type", "id_token code");
    params.put("state", state);
    params.put("client_id", CONSENT_CLIENT_ID);
    params.put("scope", CONSENT_SCOPE);
    return new AuthRequest(AUTH_URL + "?" + form(params), state, "", launcherReferrer());
  }

  Tokens exchangeLauncherCode(AuthRequest request, String code) throws IOException, InterruptedException {
    LinkedHashMap<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "authorization_code");
    form.put("client_id", LAUNCHER_CLIENT_ID);
    form.put("redirect_uri", LAUNCHER_REDIRECT_URI);
    form.put("code", code);
    if (!request.codeVerifier.isEmpty()) {
      form.put("code_verifier", request.codeVerifier);
    }
    HttpRequest tokenRequest = HttpRequest.newBuilder(URI.create(TOKEN_URL))
        .timeout(Duration.ofSeconds(30))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(form(form)))
        .build();
    HttpResponse<String> response = http.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
    BandwidthAudit.httpExchange("launcher-token", tokenRequest, response);
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw new IllegalStateException("launcher token exchange failed with HTTP " + response.statusCode()
          + ": " + safeHttpError(response.body()));
    }
    Map<String, Object> body = Json.asObject(Json.parse(response.body()));
    String accessToken = Json.string(body.get("access_token"));
    String refreshToken = Json.string(body.get("refresh_token"));
    String idToken = Json.string(body.get("id_token"));
    long expiresIn = Json.number(body.get("expires_in")).longValue();
    if (accessToken.isEmpty() || refreshToken.isEmpty() || idToken.isEmpty() || expiresIn <= 0) {
      throw new IllegalStateException("launcher token response was missing required token fields");
    }
    long expiresAt = System.currentTimeMillis() + expiresIn * 1000L;
    String loginProvider = Json.string(jwtClaims(idToken).get("login_provider"));
    if (loginProvider.isEmpty()) {
      loginProvider = "jagex";
    }
    return new Tokens(accessToken, refreshToken, idToken, expiresAt, loginProvider);
  }

  GameSession fetchGameSession(String idToken) throws IOException, InterruptedException {
    LinkedHashMap<String, Object> body = new LinkedHashMap<>();
    body.put("idToken", idToken);
    HttpRequest sessionRequest = HttpRequest.newBuilder(URI.create(GAME_SESSION_URL))
        .timeout(GAME_SESSION_CREATE_HTTP_TIMEOUT)
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(Json.stringify(body)))
        .build();
    HttpResponse<String> sessionResponse = sendGameSessionRequest("session create", sessionRequest, false);
    int sessionStatus = sessionResponse.statusCode();
    if (sessionStatus == 409 && idTokenAlreadyUsed(sessionResponse.body())) {
      throw new IOException("game-session create rejected a previously consumed consent token: "
          + safeHttpError(sessionResponse.body()));
    }
    if (isTemporaryGameSessionStatus(sessionStatus)) {
      throw new IOException("game-session create temporary HTTP " + sessionStatus + ": "
          + safeHttpError(sessionResponse.body()));
    }
    if (sessionStatus < 200 || sessionStatus >= 300) {
      throw new IllegalStateException("game-session create failed with HTTP " + sessionStatus
          + ": " + safeHttpError(sessionResponse.body()));
    }
    String sessionId = Json.string(Json.asObject(Json.parse(sessionResponse.body())).get("sessionId"));
    if (sessionId.isEmpty()) {
      throw new IllegalStateException("game-session response did not include a sessionId");
    }

    HttpRequest accountsRequest = HttpRequest.newBuilder(URI.create(GAME_ACCOUNTS_URL))
        .timeout(GAME_SESSION_LIST_HTTP_TIMEOUT)
        .header("Authorization", "Bearer " + sessionId)
        .GET()
        .build();
    HttpResponse<String> accountsResponse = sendGameSessionRequest("accounts list", accountsRequest, true);
    int accountsStatus = accountsResponse.statusCode();
    if (isTemporaryGameSessionStatus(accountsStatus)) {
      throw new IOException("game-session account list temporary HTTP " + accountsStatus + ": "
          + safeHttpError(accountsResponse.body()));
    }
    if (accountsStatus < 200 || accountsStatus >= 300) {
      throw new IllegalStateException("game-session account list failed with HTTP " + accountsStatus
          + ": " + safeHttpError(accountsResponse.body()));
    }
    ArrayList<CharacterAccount> accounts = new ArrayList<>();
    for (Object item : Json.asList(Json.parse(accountsResponse.body()))) {
      Map<String, Object> row = Json.asObject(item);
      String accountId = Json.string(row.get("accountId"));
      String displayName = Json.string(row.get("displayName"));
      if (!accountId.isEmpty()) {
        accounts.add(new CharacterAccount(accountId, displayName));
      }
    }
    if (accounts.isEmpty()) {
      throw new IllegalStateException("Jagex returned no character accounts for this login");
    }
    return new GameSession(sessionId, accounts);
  }

  private HttpResponse<String> sendGameSessionRequest(String label, HttpRequest request,
      boolean retryOnTimeout) throws IOException, InterruptedException {
    IOException lastIo = null;
    HttpResponse<String> lastResponse = null;
    for (int attempt = 1; attempt <= GAME_SESSION_HTTP_RETRIES; attempt++) {
      long startedAt = System.currentTimeMillis();
      log.accept("game-session " + label + " attempt " + attempt + "/" + GAME_SESSION_HTTP_RETRIES + " starting");
      try {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        BandwidthAudit.httpExchange("game-session-" + label.replace(' ', '-'), request, response);
        lastResponse = response;
        int status = response.statusCode();
        long elapsedMs = System.currentTimeMillis() - startedAt;
        log.accept("game-session " + label + " attempt " + attempt + "/" + GAME_SESSION_HTTP_RETRIES
            + " returned HTTP " + status + " after " + elapsedMs + "ms");
        if ((status == 429 || status >= 500) && attempt < GAME_SESSION_HTTP_RETRIES) {
          Thread.sleep(Math.min(15_000L, 3_000L * attempt));
          continue;
        }
        return response;
      } catch (IOException exception) {
        lastIo = exception;
        long elapsedMs = System.currentTimeMillis() - startedAt;
        log.accept("game-session " + label + " attempt " + attempt + "/" + GAME_SESSION_HTTP_RETRIES
            + " failed after " + elapsedMs + "ms: " + exception.getClass().getSimpleName()
            + " " + safeHttpError(exception.getMessage()));
        if (exception instanceof HttpTimeoutException && !retryOnTimeout) {
          throw new HttpTimeoutException("game-session " + label + " request timed out after "
              + attempt + " attempt" + (attempt == 1 ? "" : "s"));
        }
        if (attempt >= GAME_SESSION_HTTP_RETRIES) {
          if (exception instanceof HttpTimeoutException) {
            throw new HttpTimeoutException("game-session " + label + " request timed out after "
                + GAME_SESSION_HTTP_RETRIES + " attempts");
          }
          throw exception;
        }
        Thread.sleep(Math.min(15_000L, 3_000L * attempt));
      }
    }
    if (lastIo != null) {
      throw lastIo;
    }
    if (lastResponse != null) {
      return lastResponse;
    }
    throw new IOException("game-session request did not produce a response");
  }

  private boolean isTemporaryGameSessionStatus(int status) {
    return status == 408 || status == 425 || status == 429 || status >= 500;
  }

  private boolean idTokenAlreadyUsed(String body) {
    return safeHttpError(body).toUpperCase(Locale.ROOT).contains("ID_TOKEN_ALREADY_USED");
  }

  RunescapeProfile fetchRunescapeProfile(String idToken) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(RS_PROFILE_URL))
        .timeout(Duration.ofSeconds(30))
        .header("Authorization", "Bearer " + idToken)
        .GET()
        .build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
    BandwidthAudit.httpExchange("rs-profile", request, response);
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw new IllegalStateException("RuneScape profile lookup failed with HTTP " + response.statusCode()
          + ": " + safeHttpError(response.body()));
    }
    Map<String, Object> body = Json.asObject(Json.parse(response.body()));
    return new RunescapeProfile(
        Boolean.TRUE.equals(body.get("display_name_set")),
        Json.string(body.get("display_name")));
  }

  static Callback findCallback(List<String> urls, String expectedState) {
    for (String url : urls) {
      Callback callback = parseCallback(url, expectedState);
      if (callback != null) {
        return callback;
      }
    }
    return null;
  }

  static Callback parseCallback(String rawUrl, String expectedState) {
    if (rawUrl == null || rawUrl.isEmpty()) {
      return null;
    }
    String trimmed = rawUrl.trim();
    LinkedHashMap<String, String> values = new LinkedHashMap<>();
    if (trimmed.toLowerCase(Locale.ROOT).startsWith("jagex:")) {
      parseCommaPairs(trimmed.substring("jagex:".length()), values);
    } else {
      int queryStart = trimmed.indexOf('?');
      if (queryStart >= 0) {
        int queryEnd = trimmed.indexOf('#', queryStart);
        parseAmpPairs(trimmed.substring(queryStart + 1, queryEnd >= 0 ? queryEnd : trimmed.length()), values);
      }
      int hash = trimmed.indexOf('#');
      if (hash >= 0 && hash + 1 < trimmed.length()) {
        parseAmpPairs(trimmed.substring(hash + 1), values);
      }
    }
    String state = values.getOrDefault("state", "");
    if (expectedState != null && !expectedState.isEmpty() && !expectedState.equals(state)) {
      return null;
    }
    String code = values.getOrDefault("code", "");
    String idToken = values.getOrDefault("id_token", "");
    if (code.isEmpty() && idToken.isEmpty()) {
      return null;
    }
    return new Callback(code, idToken, state, values.getOrDefault("intent", ""));
  }

  private static Map<String, Object> jwtClaims(String jwt) {
    String[] parts = jwt.split("\\.");
    if (parts.length < 2) {
      return new LinkedHashMap<>();
    }
    byte[] decoded = Base64.getUrlDecoder().decode(padBase64(parts[1]));
    return Json.asObject(Json.parse(new String(decoded, StandardCharsets.UTF_8)));
  }

  private static String padBase64(String value) {
    int mod = value.length() % 4;
    if (mod == 0) {
      return value;
    }
    return value + "====".substring(0, 4 - mod);
  }

  private static String form(Map<String, String> values) {
    ArrayList<String> pairs = new ArrayList<>();
    for (Map.Entry<String, String> entry : values.entrySet()) {
      pairs.add(urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()));
    }
    return String.join("&", pairs);
  }

  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static String urlDecode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  private static String codeChallenge(String verifier) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String launcherReferrer() {
    return "";
  }

  private static String randomLauncherReferrerToken() {
    return randomUrlToken(24)
        .replace('_', 'a')
        .replace('-', 'b')
        .toLowerCase(Locale.ENGLISH);
  }

  private static String randomUrlToken(int byteCount) {
    byte[] bytes = new byte[byteCount];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static void parseAmpPairs(String text, Map<String, String> out) {
    if (text == null || text.isEmpty()) {
      return;
    }
    for (String piece : text.split("&")) {
      int equals = piece.indexOf('=');
      if (equals <= 0) {
        continue;
      }
      out.put(urlDecode(piece.substring(0, equals)), urlDecode(piece.substring(equals + 1)));
    }
  }

  private static void parseCommaPairs(String text, Map<String, String> out) {
    for (String piece : text.split(",")) {
      int equals = piece.indexOf('=');
      if (equals <= 0) {
        continue;
      }
      out.put(urlDecode(piece.substring(0, equals)), urlDecode(piece.substring(equals + 1)));
    }
  }

  private static String randomAlnum(int length) {
    StringBuilder out = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      out.append(ALNUM[RANDOM.nextInt(ALNUM.length)]);
    }
    return out.toString();
  }

  private static String safeHttpError(String body) {
    String text = DiagnosticSanitizer.sanitize(body == null ? "" : body.replaceAll("\\s+", " ").trim());
    if (text.length() > 240) {
      return text.substring(0, 240);
    }
    return text;
  }

  private void configureProxy(HttpClient.Builder builder, ProxyConfig proxy) {
    if (proxy == null || !proxy.enabled()) {
      return;
    }
    try {
      URI uri = proxy.uri();
      String scheme = String.valueOf(uri.getScheme() == null ? "" : uri.getScheme()).toLowerCase(Locale.ROOT);
      String host = uri.getHost();
      int port = uri.getPort();
      if (host == null || host.isBlank() || port <= 0) {
        log.accept("game-session proxy ignored; could not parse configured proxy");
        return;
      }
      if (scheme.startsWith("socks")) {
        System.setProperty("socksProxyHost", host);
        System.setProperty("socksProxyPort", String.valueOf(port));
        if (proxy.hasCredentials()) {
          System.setProperty("java.net.socks.username", proxy.username());
        }
        if (!proxy.password().isEmpty()) {
          System.setProperty("java.net.socks.password", proxy.password());
        }
        log.accept("game-session HTTP client using configured SOCKS proxy");
        return;
      }
      builder.proxy(ProxySelector.of(new InetSocketAddress(host, port)));
      if (proxy.hasCredentials()) {
        String proxyUser = proxy.username();
        char[] proxyPassword = proxy.password().toCharArray();
        builder.authenticator(new java.net.Authenticator() {
          @Override
          protected java.net.PasswordAuthentication getPasswordAuthentication() {
            return new java.net.PasswordAuthentication(proxyUser, proxyPassword);
          }
        });
      }
      log.accept("game-session HTTP client using configured proxy");
    } catch (Exception exception) {
      log.accept("game-session proxy ignored; invalid configured proxy (" + exception.getClass().getSimpleName() + ")");
    }
  }

  static final class AuthRequest {
    final String url;
    final String state;
    final String codeVerifier;
    final String referrer;

    AuthRequest(String url, String state, String codeVerifier, String referrer) {
      this.url = url;
      this.state = state;
      this.codeVerifier = codeVerifier == null ? "" : codeVerifier;
      this.referrer = referrer == null ? "" : referrer;
    }
  }

  static final class Callback {
    final String code;
    final String idToken;
    final String state;
    final String intent;

    Callback(String code, String idToken, String state, String intent) {
      this.code = code == null ? "" : code;
      this.idToken = idToken == null ? "" : idToken;
      this.state = state == null ? "" : state;
      this.intent = intent == null ? "" : intent;
    }
  }

  static final class Tokens {
    final String accessToken;
    final String refreshToken;
    final String idToken;
    final long expiresAt;
    final String loginProvider;

    Tokens(String accessToken, String refreshToken, String idToken, long expiresAt, String loginProvider) {
      this.accessToken = accessToken;
      this.refreshToken = refreshToken;
      this.idToken = idToken;
      this.expiresAt = expiresAt;
      this.loginProvider = loginProvider;
    }
  }

  static final class CharacterAccount {
    final String accountId;
    final String displayName;

    CharacterAccount(String accountId, String displayName) {
      this.accountId = accountId;
      this.displayName = displayName == null ? "" : displayName;
    }
  }

  static final class GameSession {
    final String sessionId;
    final List<CharacterAccount> accounts;

    GameSession(String sessionId, List<CharacterAccount> accounts) {
      this.sessionId = sessionId;
      this.accounts = accounts;
    }
  }

  static final class RunescapeProfile {
    final boolean displayNameSet;
    final String displayName;

    RunescapeProfile(boolean displayNameSet, String displayName) {
      this.displayNameSet = displayNameSet;
      this.displayName = displayName == null ? "" : displayName;
    }
  }
}
