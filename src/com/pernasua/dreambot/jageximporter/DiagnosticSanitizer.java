package com.pernasua.dreambot.jageximporter;

import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class DiagnosticSanitizer {
  private static final String REDACTED = "<redacted>";
  private static final Pattern ACCOUNT_ROW = Pattern.compile(
      "(?i)\\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\\.[A-Z]{2,63}:[^\\s:]+:[A-Z2-7]{16,128}\\b");
  private static final Pattern EMAIL = Pattern.compile(
      "(?i)\\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\\.[A-Z]{2,63}\\b");
  private static final Pattern URL_USERINFO = Pattern.compile(
      "(?i)\\b([a-z][a-z0-9+.-]*://)([^\\s/@:]+):([^\\s/@]+)@");
  private static final Pattern URL_PARAM = Pattern.compile(
      "(?i)([?&#,;]\\s*(?:code|id_token|access_token|refresh_token|session_id|sessionId|idToken"
          + "|token|password|secret|otp|totp|state|nonce|code_verifier|code_challenge|email|username)="
          + ")([^&#,;\\s\"'<>)]*)");
  private static final Pattern JSON_STRING_FIELD = Pattern.compile(
      "(?i)(\"(?:email|username|password|pass|pwd|pin|secret|otp|totp|access[_-]?token"
          + "|refresh[_-]?token|id[_-]?token|session(?:id)?|authorization|code[_-]?verifier"
          + "|code[_-]?challenge|state|nonce)\"\\s*:\\s*\")([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
  private static final Pattern KEY_VALUE = Pattern.compile(
      "(?i)\\b(email|username|password|pass|pwd|pin|secret|otp|totp|access[_-]?token"
          + "|refresh[_-]?token|id[_-]?token|idToken|sessionId|authorization|code_verifier"
          + "|code_challenge|state|nonce)\\s*[:=]\\s*([^\\s,;&)\\]}]+)");
  private static final Pattern BEARER = Pattern.compile("(?i)\\bBearer\\s+[-._~+/A-Za-z0-9]+=*");
  private static final Pattern JWT = Pattern.compile(
      "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{8,}\\b");
  private static final Pattern OTPAUTH = Pattern.compile("(?i)otpauth://[^\\s\"'<>]+");
  private static final Pattern LABELED_BASE32 = Pattern.compile(
      "(?i)\\b((?:totp|otp|authenticator|setup|manual|secret)\\s+(?:secret|key|code)?"
          + "[^A-Z2-7]{0,40})([A-Z2-7]{16,128})\\b");
  private static final Pattern LABELED_DIGIT_CODE = Pattern.compile(
      "(?i)\\b((?:verification|security|email|login|authenticator|totp|otp|one-time)"
          + "\\s*(?:code)?\\s*(?:is|was|:|=)?\\s*)(\\d{6,8})\\b");

  private DiagnosticSanitizer() {
  }

  static Consumer<String> consumer(Consumer<String> sink) {
    Consumer<String> target = sink == null ? ignored -> { } : sink;
    return message -> target.accept(sanitize(message));
  }

  static String sanitize(String text, String... exactValues) {
    String out = text == null ? "" : text;
    if (exactValues != null) {
      for (String value : exactValues) {
        if (value != null && !value.isEmpty()) {
          out = out.replace(value, REDACTED);
        }
      }
    }
    out = ACCOUNT_ROW.matcher(out).replaceAll("<account-row>");
    out = URL_USERINFO.matcher(out).replaceAll("$1<credentials>@");
    out = replaceUrlParams(out);
    out = JSON_STRING_FIELD.matcher(out).replaceAll("$1" + REDACTED + "\"");
    out = KEY_VALUE.matcher(out).replaceAll("$1=" + REDACTED);
    out = BEARER.matcher(out).replaceAll("Bearer " + REDACTED);
    out = JWT.matcher(out).replaceAll("<jwt>");
    out = OTPAUTH.matcher(out).replaceAll("otpauth://<redacted>");
    out = LABELED_BASE32.matcher(out).replaceAll("$1" + REDACTED);
    out = LABELED_DIGIT_CODE.matcher(out).replaceAll("$1" + REDACTED);
    out = EMAIL.matcher(out).replaceAll("<email>");
    return out;
  }

  static String sanitizeUrl(String value) {
    return sanitize(value);
  }

  private static String replaceUrlParams(String input) {
    Matcher matcher = URL_PARAM.matcher(input);
    StringBuffer out = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(out, Matcher.quoteReplacement(matcher.group(1) + REDACTED));
    }
    matcher.appendTail(out);
    return out.toString();
  }
}
