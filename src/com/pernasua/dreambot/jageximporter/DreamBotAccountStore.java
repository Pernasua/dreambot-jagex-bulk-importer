package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class DreamBotAccountStore {
  static final byte[] TINK_PREFIX = hex("0148966ee1");
  private static final byte[] AES_GCM_KEY = hex("5499df0e05a05f80e9b8d779bb7316b9080652830fa5e406c13c74ad95c54be2");
  static final int BUILT_IN_AAD_INT = 152984;
  private static final int AAD_SCAN_START = 0;
  private static final int AAD_SCAN_END = 2_000_000;
  static final int NONCE_BYTES = 12;
  private static final Map<String, Integer> AAD_CACHE = new LinkedHashMap<>();
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final DateTimeFormatter BACKUP_STAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

  private DreamBotAccountStore() {
  }

  static Info info(Path db) throws IOException, GeneralSecurityException {
    DecodedStore decoded = readDecoded(db);
    return new Info(decoded.rows.size(), codecLabel(decoded.aad), decoded.aad);
  }

  static BackupContext backupContext() {
    return new BackupContext();
  }

  static AddResult addJagexAccount(Path db, DreamBotJagexBulkImporter.AccountRow account,
      JagexOAuthClient.Tokens tokens, JagexOAuthClient.GameSession session,
      BackupContext backupContext) throws Exception {
    Path lockPath = db.resolveSibling(db.getFileName() + ".lock");
    Files.createDirectories(db.toAbsolutePath().getParent());
    try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock ignored = channel.lock()) {
      DecodedStore decoded = readDecoded(db);
      ArrayList<Map<String, Object>> rows = new ArrayList<>(decoded.rows);
      int before = rows.size();
      Set<String> characterIds = new HashSet<>();
      Set<String> labels = new HashSet<>();
      for (Map<String, Object> row : rows) {
        String characterId = Json.string(row.get("characterId"));
        if (!characterId.isEmpty()) {
          characterIds.add(characterId);
        }
        labels.add(Json.string(row.get("nickname")).toLowerCase(Locale.ROOT));
        labels.add(Json.string(row.get("username")).toLowerCase(Locale.ROOT));
      }

      ArrayList<String> addedLabels = new ArrayList<>();
      for (JagexOAuthClient.CharacterAccount character : session.accounts) {
        String label = label(account.email, character.accountId);
        if (characterIds.contains(character.accountId)
            || labels.contains(label.toLowerCase(Locale.ROOT))) {
          continue;
        }
        rows.add(record(label, account, tokens, session.sessionId, character.accountId));
        addedLabels.add(label);
        characterIds.add(character.accountId);
        labels.add(label.toLowerCase(Locale.ROOT));
      }

      if (addedLabels.isEmpty()) {
        return new AddResult(before, rows.size(), 0, List.of(), null);
      }
      Path backup = backupContext == null ? backup(db) : backupContext.ensure(db);
      write(db, rows, decoded.aad);
      int persisted = verifyPersistedCount(db, rows.size());
      return new AddResult(before, persisted, addedLabels.size(), addedLabels, backup);
    }
  }

  static AddResult addLegacyAccount(Path db, DreamBotJagexBulkImporter.AccountRow account,
      JagexOAuthClient.RunescapeProfile profile, BackupContext backupContext) throws Exception {
    Path lockPath = db.resolveSibling(db.getFileName() + ".lock");
    Files.createDirectories(db.toAbsolutePath().getParent());
    try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock ignored = channel.lock()) {
      DecodedStore decoded = readDecoded(db);
      ArrayList<Map<String, Object>> rows = new ArrayList<>(decoded.rows);
      int before = rows.size();
      String usernameKey = account.email.toLowerCase(Locale.ROOT);
      for (Map<String, Object> row : rows) {
        if (usernameKey.equals(Json.string(row.get("username")).toLowerCase(Locale.ROOT))
            || usernameKey.equals(Json.string(row.get("nickname")).toLowerCase(Locale.ROOT))) {
          return new AddResult(before, rows.size(), 0, List.of(), null);
        }
      }
      rows.add(classicRecord(account, nickname(account, profile)));
      Path backup = backupContext == null ? backup(db) : backupContext.ensure(db);
      write(db, rows, decoded.aad);
      int persisted = verifyPersistedCount(db, rows.size());
      return new AddResult(before, persisted, 1, List.of(account.email), backup);
    }
  }

  static List<Map<String, Object>> read(Path db) throws IOException, GeneralSecurityException {
    return readDecoded(db).rows;
  }

  private static DecodedStore readDecoded(Path db) throws IOException, GeneralSecurityException {
    if (!Files.isRegularFile(db)) {
      throw new IllegalArgumentException("accounts.db does not exist: " + db);
    }
    byte[] encrypted = Files.readAllBytes(db);
    if (encrypted.length == 0) {
      return new DecodedStore(new ArrayList<>(), BUILT_IN_AAD_INT);
    }
    DecodeAttempt failure = null;
    int checked = 0;
    Integer cached = cachedAad(db);
    if (cached != null) {
      DecodeAttempt attempt = tryDecode(encrypted, cached);
      checked++;
      if (attempt.rows != null) {
        return new DecodedStore(attempt.rows, cached);
      }
      failure = attempt;
    }
    if (cached == null || cached != BUILT_IN_AAD_INT) {
      DecodeAttempt attempt = tryDecode(encrypted, BUILT_IN_AAD_INT);
      checked++;
      if (attempt.rows != null) {
        rememberAad(db, BUILT_IN_AAD_INT);
        return new DecodedStore(attempt.rows, BUILT_IN_AAD_INT);
      }
      failure = attempt;
    }
    int rangeStart = Math.max(0, Math.min(AAD_SCAN_START, AAD_SCAN_END));
    int rangeEnd = Math.max(AAD_SCAN_START, AAD_SCAN_END);
    for (int aad = rangeStart; aad <= rangeEnd; aad++) {
      if ((cached != null && aad == cached) || aad == BUILT_IN_AAD_INT) {
        continue;
      }
      DecodeAttempt attempt = tryDecode(encrypted, aad);
      checked++;
      if (attempt.rows != null) {
        rememberAad(db, aad);
        return new DecodedStore(attempt.rows, aad);
      }
      failure = attempt;
    }
    throw unsupportedDbException(db, encrypted, failure == null ? null : failure.failure, checked);
  }

  private static DecodeAttempt tryDecode(byte[] encrypted, int aad) {
    try {
      return new DecodeAttempt(parseRows(decrypt(encrypted, aad)), null);
    } catch (GeneralSecurityException | RuntimeException exception) {
      return new DecodeAttempt(null, exception);
    }
  }

  private static ArrayList<Map<String, Object>> parseRows(byte[] plain) {
    Object parsed = Json.parse(new String(plain, StandardCharsets.UTF_8));
    ArrayList<Map<String, Object>> rows = new ArrayList<>();
    for (Object item : Json.asList(parsed)) {
      rows.add(new LinkedHashMap<>(Json.asObject(item)));
    }
    return rows;
  }

  private static void write(Path db, List<Map<String, Object>> rows, int aad)
      throws IOException, GeneralSecurityException {
    byte[] plain = Json.stringify(rows).getBytes(StandardCharsets.UTF_8);
    byte[] encrypted = encrypt(plain, aad);
    Path tmp = db.resolveSibling(db.getFileName() + ".tmp-" + ProcessHandle.current().pid());
    Files.write(tmp, encrypted, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    try {
      Files.setPosixFilePermissions(tmp, java.util.Set.of(
          java.nio.file.attribute.PosixFilePermission.OWNER_READ,
          java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
    } catch (UnsupportedOperationException ignored) {
      // Windows.
    }
    Files.move(tmp, db, StandardCopyOption.REPLACE_EXISTING);
  }

  static void writeForTest(Path db, List<Map<String, Object>> rows) throws IOException, GeneralSecurityException {
    write(db, rows, BUILT_IN_AAD_INT);
  }

  static void writeForTest(Path db, List<Map<String, Object>> rows, int aad)
      throws IOException, GeneralSecurityException {
    write(db, rows, aad);
  }

  private static int verifyPersistedCount(Path db, int expected) throws IOException, GeneralSecurityException {
    int persisted = read(db).size();
    if (persisted != expected) {
      throw new IOException("accounts.db write verification failed: expected " + expected
          + " account(s), found " + persisted);
    }
    return persisted;
  }

  private static Map<String, Object> record(String label, DreamBotJagexBulkImporter.AccountRow account,
      JagexOAuthClient.Tokens tokens, String sessionId, String characterId) {
    LinkedHashMap<String, Object> row = new LinkedHashMap<>();
    row.put("nickname", label);
    row.put("username", label);
    row.put("password", account.password);
    row.put("pin", "");
    row.put("totp", "");
    row.put("characterId", characterId);
    row.put("sessionId", sessionId);
    row.put("ssoEmail", account.email);
    row.put("ssoPassword", account.password);
    row.put("accessToken", tokens.accessToken);
    row.put("refreshToken", tokens.refreshToken);
    row.put("expiresAt", tokens.expiresAt);
    row.put("banned", false);
    return row;
  }

  private static Map<String, Object> classicRecord(DreamBotJagexBulkImporter.AccountRow account, String nickname) {
    LinkedHashMap<String, Object> row = new LinkedHashMap<>();
    row.put("nickname", nickname);
    row.put("username", account.email);
    row.put("password", account.password);
    row.put("pin", "");
    row.put("totp", Totp.normalizeSecret(account.otpSecret));
    row.put("banned", false);
    return row;
  }

  private static String nickname(DreamBotJagexBulkImporter.AccountRow account,
      JagexOAuthClient.RunescapeProfile profile) {
    if (profile != null && profile.displayNameSet && !profile.displayName.isBlank()) {
      return profile.displayName;
    }
    return account.email;
  }

  private static String label(String email, String characterId) {
    return email + " (" + characterId + ")";
  }

  private static Path backup(Path db) throws IOException {
    Path backup = db.resolveSibling(db.getFileName() + ".bak-" + BACKUP_STAMP.format(Instant.now()));
    Files.copy(db, backup, StandardCopyOption.REPLACE_EXISTING);
    return backup;
  }

  private static GeneralSecurityException unsupportedDbException(Path db, byte[] encrypted, Exception builtInFailure,
      int checked) {
    StringBuilder message = new StringBuilder();
    message.append("accounts.db could not be decrypted. ");
    if (hasTinkPrefix(encrypted)) {
      message.append("It has the DreamBot/Tink prefix ")
          .append(hex(TINK_PREFIX))
          .append(", but it did not authenticate with any scanned AAD value. ");
    } else {
      message.append("It does not have the expected DreamBot/Tink prefix ")
          .append(hex(TINK_PREFIX))
          .append(". ");
    }
    message.append("Checked ").append(checked).append(" AAD value(s). ")
        .append("Close DreamBot and copy BotData/accounts.db again. ")
        .append("If DreamBot can read this same file, this likely means DreamBot rotated the account-store key, not just the AAD. ")
        .append("File: ").append(db.toAbsolutePath().normalize());
    GeneralSecurityException exception = new GeneralSecurityException(message.toString());
    if (builtInFailure != null) {
      exception.initCause(builtInFailure);
    }
    return exception;
  }

  private static boolean hasTinkPrefix(byte[] encrypted) {
    if (encrypted.length < TINK_PREFIX.length) {
      return false;
    }
    for (int i = 0; i < TINK_PREFIX.length; i++) {
      if (encrypted[i] != TINK_PREFIX[i]) {
        return false;
      }
    }
    return true;
  }

  private static byte[] decrypt(byte[] encrypted, int aadInt) throws GeneralSecurityException {
    if (encrypted.length < TINK_PREFIX.length + NONCE_BYTES + 16) {
      throw new GeneralSecurityException("accounts.db is too short to be a DreamBot account database");
    }
    for (int i = 0; i < TINK_PREFIX.length; i++) {
      if (encrypted[i] != TINK_PREFIX[i]) {
        throw new GeneralSecurityException("accounts.db has an unexpected encryption prefix");
      }
    }
    byte[] nonce = java.util.Arrays.copyOfRange(encrypted, TINK_PREFIX.length, TINK_PREFIX.length + NONCE_BYTES);
    byte[] ciphertext = java.util.Arrays.copyOfRange(encrypted, TINK_PREFIX.length + NONCE_BYTES, encrypted.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AES_GCM_KEY, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aadBytes(aadInt));
    return cipher.doFinal(ciphertext);
  }

  private static byte[] encrypt(byte[] plain, int aadInt) throws GeneralSecurityException {
    byte[] nonce = new byte[NONCE_BYTES];
    RANDOM.nextBytes(nonce);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_GCM_KEY, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aadBytes(aadInt));
    byte[] ciphertext = cipher.doFinal(plain);
    byte[] out = new byte[TINK_PREFIX.length + nonce.length + ciphertext.length];
    System.arraycopy(TINK_PREFIX, 0, out, 0, TINK_PREFIX.length);
    System.arraycopy(nonce, 0, out, TINK_PREFIX.length, nonce.length);
    System.arraycopy(ciphertext, 0, out, TINK_PREFIX.length + nonce.length, ciphertext.length);
    return out;
  }

  private static byte[] aadBytes(int aadInt) {
    return ByteBuffer.allocate(4).putInt(aadInt).array();
  }

  private static Integer cachedAad(Path db) {
    synchronized (AAD_CACHE) {
      return AAD_CACHE.get(cacheKey(db));
    }
  }

  private static void rememberAad(Path db, int aad) {
    synchronized (AAD_CACHE) {
      AAD_CACHE.put(cacheKey(db), aad);
    }
  }

  private static String cacheKey(Path db) {
    return db.toAbsolutePath().normalize().toString();
  }

  private static String codecLabel(int aad) {
    return aad == BUILT_IN_AAD_INT ? "built-in" : "aes-gcm-aad";
  }

  static byte[] hex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  static String hex(byte[] value) {
    StringBuilder out = new StringBuilder(value.length * 2);
    for (byte item : value) {
      out.append(String.format("%02x", item & 0xff));
    }
    return out.toString();
  }

  static final class Info {
    final int count;
    final String codec;
    final Integer aad;

    Info(int count, String codec, Integer aad) {
      this.count = count;
      this.codec = codec;
      this.aad = aad;
    }
  }

  private static final class DecodeAttempt {
    final ArrayList<Map<String, Object>> rows;
    final Exception failure;

    DecodeAttempt(ArrayList<Map<String, Object>> rows, Exception failure) {
      this.rows = rows;
      this.failure = failure;
    }
  }

  private static final class DecodedStore {
    final List<Map<String, Object>> rows;
    final int aad;

    DecodedStore(List<Map<String, Object>> rows, int aad) {
      this.rows = rows;
      this.aad = aad;
    }
  }

  static final class BackupContext {
    private Path backup;

    Path ensure(Path db) throws IOException {
      if (backup == null) {
        backup = backup(db);
      }
      return backup;
    }

    Path path() {
      return backup;
    }
  }

  static final class AddResult {
    final int beforeCount;
    final int afterCount;
    final int addedCount;
    final List<String> addedLabels;
    final Path backup;

    AddResult(int beforeCount, int afterCount, int addedCount, List<String> addedLabels, Path backup) {
      this.beforeCount = beforeCount;
      this.afterCount = afterCount;
      this.addedCount = addedCount;
      this.addedLabels = addedLabels;
      this.backup = backup;
    }
  }
}
