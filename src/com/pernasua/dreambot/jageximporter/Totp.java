package com.pernasua.dreambot.jageximporter;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class Totp {
  private Totp() {
  }

  static String normalizeSecret(String value) {
    return extractOtpauthSecret(String.valueOf(value == null ? "" : value).trim())
        .replaceAll("[\\s-]+", "")
        .replaceAll("=+$", "")
        .toUpperCase(Locale.ROOT);
  }

  // Accept a full otpauth:// URI (the kind copied from a QR-code export) and pull out the secret=
  // parameter, so a pasted URI is not treated as the raw secret.
  private static String extractOtpauthSecret(String raw) {
    if (raw.toLowerCase(Locale.ROOT).indexOf("otpauth://") < 0) {
      return raw;
    }
    int query = raw.indexOf('?');
    if (query < 0) {
      return raw;
    }
    for (String param : raw.substring(query + 1).split("&")) {
      int eq = param.indexOf('=');
      if (eq > 0 && param.substring(0, eq).trim().equalsIgnoreCase("secret")) {
        return param.substring(eq + 1).trim();
      }
    }
    return raw;
  }

  static void validateSecret(String value) {
    byte[] decoded = decodeBase32(value);
    if (decoded.length == 0) {
      throw new IllegalArgumentException("OTP secret is empty");
    }
  }

  static Code generate(String secret) {
    return generate(secret, Instant.now(), 30, 6);
  }

  static Code generate(String secret, Instant now, int period, int digits) {
    if (period <= 0) {
      throw new IllegalArgumentException("TOTP period must be positive");
    }
    if (digits < 6 || digits > 10) {
      throw new IllegalArgumentException("TOTP digits must be between 6 and 10");
    }
    byte[] key = decodeBase32(secret);
    long epochSeconds = now.getEpochSecond();
    long counter = epochSeconds / period;
    byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
    byte[] digest;
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(key, "HmacSHA1"));
      digest = mac.doFinal(counterBytes);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("could not generate TOTP", exception);
    }
    int offset = digest[digest.length - 1] & 0x0F;
    int binary = ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF);
    long divisor = 1;
    for (int i = 0; i < digits; i++) {
      divisor *= 10;
    }
    String format = "%0" + digits + "d";
    int remaining = period - (int) (epochSeconds % period);
    return new Code(String.format(Locale.ROOT, format, binary % divisor), remaining, period, counter);
  }

  private static byte[] decodeBase32(String value) {
    String clean = normalizeSecret(value);
    if (clean.isEmpty()) {
      throw new IllegalArgumentException("OTP secret is required");
    }
    if (!clean.matches("[A-Z2-7]+")) {
      String offenders = clean.replaceAll("[A-Z2-7]", "");
      throw new IllegalArgumentException("OTP secret is not valid base32 (offending characters: \""
          + offenders + "\"). Base32 uses A-Z and 2-7 only; 0/1/8/9 are not valid, and O/I are often"
          + " mistyped for 0/1. Make sure this is the authenticator seed, not a recovery code.");
    }

    int outputLength = clean.length() * 5 / 8;
    byte[] output = new byte[outputLength];
    int buffer = 0;
    int bitsLeft = 0;
    int index = 0;
    for (int i = 0; i < clean.length(); i++) {
      int value5 = base32Value(clean.charAt(i));
      buffer = (buffer << 5) | value5;
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        output[index++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
        bitsLeft -= 8;
      }
    }
    if (index == output.length) {
      return output;
    }
    byte[] trimmed = new byte[index];
    System.arraycopy(output, 0, trimmed, 0, index);
    return trimmed;
  }

  private static int base32Value(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
      return ch - 'A';
    }
    if (ch >= '2' && ch <= '7') {
      return 26 + (ch - '2');
    }
    throw new IllegalArgumentException("invalid base32 character");
  }

  static final class Code {
    final String value;
    final int remainingSeconds;
    final int period;
    final long counter;

    Code(String value, int remainingSeconds, int period, long counter) {
      this.value = value;
      this.remainingSeconds = remainingSeconds;
      this.period = period;
      this.counter = counter;
    }
  }
}
