package com.pernasua.dreambot.jageximporter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
  private Json() {
  }

  static Object parse(String text) {
    return new Parser(text).parse();
  }

  static String stringify(Object value) {
    StringBuilder out = new StringBuilder();
    write(out, value);
    return out.toString();
  }

  static String quote(String value) {
    StringBuilder out = new StringBuilder();
    writeString(out, value);
    return out.toString();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> asObject(Object value) {
    if (value instanceof Map) {
      return (Map<String, Object>) value;
    }
    return new LinkedHashMap<>();
  }

  @SuppressWarnings("unchecked")
  static List<Object> asList(Object value) {
    if (value instanceof List) {
      return (List<Object>) value;
    }
    return new ArrayList<>();
  }

  static String string(Object value) {
    return value == null ? "" : String.valueOf(value);
  }

  static Number number(Object value) {
    return value instanceof Number ? (Number) value : 0;
  }

  private static void write(StringBuilder out, Object value) {
    if (value == null) {
      out.append("null");
    } else if (value instanceof String || value instanceof Character) {
      writeString(out, String.valueOf(value));
    } else if (value instanceof Number || value instanceof Boolean) {
      out.append(value);
    } else if (value instanceof Map) {
      out.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
        if (!first) {
          out.append(',');
        }
        first = false;
        writeString(out, String.valueOf(entry.getKey()));
        out.append(':');
        write(out, entry.getValue());
      }
      out.append('}');
    } else if (value instanceof Collection) {
      out.append('[');
      boolean first = true;
      for (Object item : (Collection<?>) value) {
        if (!first) {
          out.append(',');
        }
        first = false;
        write(out, item);
      }
      out.append(']');
    } else {
      writeString(out, String.valueOf(value));
    }
  }

  private static void writeString(StringBuilder out, String value) {
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\b':
          out.append("\\b");
          break;
        case '\f':
          out.append("\\f");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (ch < 0x20) {
            out.append(String.format("\\u%04x", (int) ch));
          } else {
            out.append(ch);
          }
      }
    }
    out.append('"');
  }

  private static final class Parser {
    private final String text;
    private int index;

    Parser(String text) {
      this.text = text == null ? "" : text;
    }

    Object parse() {
      skipWhitespace();
      Object value = readValue();
      skipWhitespace();
      if (index != text.length()) {
        throw error("unexpected trailing JSON content");
      }
      return value;
    }

    private Object readValue() {
      skipWhitespace();
      if (index >= text.length()) {
        throw error("unexpected end of JSON");
      }
      char ch = text.charAt(index);
      if (ch == '"') {
        return readString();
      }
      if (ch == '{') {
        return readObject();
      }
      if (ch == '[') {
        return readArray();
      }
      if (ch == 't') {
        expect("true");
        return Boolean.TRUE;
      }
      if (ch == 'f') {
        expect("false");
        return Boolean.FALSE;
      }
      if (ch == 'n') {
        expect("null");
        return null;
      }
      if (ch == '-' || Character.isDigit(ch)) {
        return readNumber();
      }
      throw error("unexpected JSON token");
    }

    private Map<String, Object> readObject() {
      LinkedHashMap<String, Object> object = new LinkedHashMap<>();
      index++;
      skipWhitespace();
      if (consume('}')) {
        return object;
      }
      while (true) {
        skipWhitespace();
        if (index >= text.length() || text.charAt(index) != '"') {
          throw error("expected JSON object key");
        }
        String key = readString();
        skipWhitespace();
        if (!consume(':')) {
          throw error("expected ':' after JSON object key");
        }
        object.put(key, readValue());
        skipWhitespace();
        if (consume('}')) {
          return object;
        }
        if (!consume(',')) {
          throw error("expected ',' in JSON object");
        }
      }
    }

    private List<Object> readArray() {
      ArrayList<Object> array = new ArrayList<>();
      index++;
      skipWhitespace();
      if (consume(']')) {
        return array;
      }
      while (true) {
        array.add(readValue());
        skipWhitespace();
        if (consume(']')) {
          return array;
        }
        if (!consume(',')) {
          throw error("expected ',' in JSON array");
        }
      }
    }

    private String readString() {
      StringBuilder out = new StringBuilder();
      index++;
      while (index < text.length()) {
        char ch = text.charAt(index++);
        if (ch == '"') {
          return out.toString();
        }
        if (ch != '\\') {
          out.append(ch);
          continue;
        }
        if (index >= text.length()) {
          throw error("unterminated JSON escape");
        }
        char escaped = text.charAt(index++);
        switch (escaped) {
          case '"':
          case '\\':
          case '/':
            out.append(escaped);
            break;
          case 'b':
            out.append('\b');
            break;
          case 'f':
            out.append('\f');
            break;
          case 'n':
            out.append('\n');
            break;
          case 'r':
            out.append('\r');
            break;
          case 't':
            out.append('\t');
            break;
          case 'u':
            if (index + 4 > text.length()) {
              throw error("short JSON unicode escape");
            }
            out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
            index += 4;
            break;
          default:
            throw error("invalid JSON escape");
        }
      }
      throw error("unterminated JSON string");
    }

    private Number readNumber() {
      int start = index;
      if (consume('-')) {
        // Sign consumed.
      }
      while (index < text.length() && Character.isDigit(text.charAt(index))) {
        index++;
      }
      boolean floating = false;
      if (consume('.')) {
        floating = true;
        while (index < text.length() && Character.isDigit(text.charAt(index))) {
          index++;
        }
      }
      if (index < text.length() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
        floating = true;
        index++;
        if (index < text.length() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
          index++;
        }
        while (index < text.length() && Character.isDigit(text.charAt(index))) {
          index++;
        }
      }
      String raw = text.substring(start, index);
      return floating ? Double.parseDouble(raw) : Long.parseLong(raw);
    }

    private void expect(String expected) {
      if (!text.startsWith(expected, index)) {
        throw error("expected " + expected);
      }
      index += expected.length();
    }

    private boolean consume(char expected) {
      if (index < text.length() && text.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    private void skipWhitespace() {
      while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
        index++;
      }
    }

    private IllegalArgumentException error(String message) {
      return new IllegalArgumentException(message + " at offset " + index);
    }
  }
}
