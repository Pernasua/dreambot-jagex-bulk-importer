package com.pernasua.dreambot.jageximporter;

import java.util.Locale;

enum BrowserEngine {
  JCEF("embedded JCEF"),
  SYSTEM("system Chrome/Edge");

  final String label;

  BrowserEngine(String label) {
    this.label = label;
  }

  static BrowserEngine parse(String value) {
    String normalized = String.valueOf(value == null ? "" : value).trim().toLowerCase(Locale.ROOT);
    switch (normalized) {
      case "":
      case "jcef":
      case "embedded":
      case "internal":
        return JCEF;
      case "system":
      case "chrome":
      case "chromium":
      case "edge":
        return SYSTEM;
      default:
        throw new IllegalArgumentException("unknown browser engine: " + value);
    }
  }
}
