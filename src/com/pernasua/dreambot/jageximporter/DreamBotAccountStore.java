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
  private static final byte[] TINK_PREFIX = hex("0148966ee1");
  private static final byte[] AES_GCM_KEY = hex("5499df0e05a05f80e9b8d779bb7316b9080652830fa5e406c13c74ad95c54be2");
  private static final byte[] AAD = ByteBuffer.allocate(4).putInt(152984).array();
  private static final int NONCE_BYTES = 12;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final DateTimeFormatter BACKUP_STAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

  private DreamBotAccountStore() {
  }

  static Info info(Path db) throws IOException, GeneralSecurityException {
    return new Info(read(db).size());
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
      ArrayList<Map<String, Object>> rows = new ArrayList<>(read(db));
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
      write(db, rows);
      return new AddResult(before, rows.size(), addedLabels.size(), addedLabels, backup);
    }
  }

  static AddResult addLegacyAccount(Path db, DreamBotJagexBulkImporter.AccountRow account,
      JagexOAuthClient.RunescapeProfile profile, BackupContext backupContext) throws Exception {
    Path lockPath = db.resolveSibling(db.getFileName() + ".lock");
    Files.createDirectories(db.toAbsolutePath().getParent());
    try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock ignored = channel.lock()) {
      ArrayList<Map<String, Object>> rows = new ArrayList<>(read(db));
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
      write(db, rows);
      return new AddResult(before, rows.size(), 1, List.of(account.email), backup);
    }
  }

  static List<Map<String, Object>> read(Path db) throws IOException, GeneralSecurityException {
    if (!Files.isRegularFile(db)) {
      throw new IllegalArgumentException("accounts.db does not exist: " + db);
    }
    byte[] encrypted = Files.readAllBytes(db);
    if (encrypted.length == 0) {
      return new ArrayList<>();
    }
    byte[] plain = decrypt(encrypted);
    Object parsed = Json.parse(new String(plain, StandardCharsets.UTF_8));
    ArrayList<Map<String, Object>> rows = new ArrayList<>();
    for (Object item : Json.asList(parsed)) {
      rows.add(new LinkedHashMap<>(Json.asObject(item)));
    }
    return rows;
  }

  private static void write(Path db, List<Map<String, Object>> rows) throws IOException, GeneralSecurityException {
    byte[] plain = Json.stringify(rows).getBytes(StandardCharsets.UTF_8);
    byte[] encrypted = encrypt(plain);
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

  private static byte[] decrypt(byte[] encrypted) throws GeneralSecurityException {
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
    cipher.updateAAD(AAD);
    return cipher.doFinal(ciphertext);
  }

  private static byte[] encrypt(byte[] plain) throws GeneralSecurityException {
    byte[] nonce = new byte[NONCE_BYTES];
    RANDOM.nextBytes(nonce);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_GCM_KEY, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(AAD);
    byte[] ciphertext = cipher.doFinal(plain);
    byte[] out = new byte[TINK_PREFIX.length + nonce.length + ciphertext.length];
    System.arraycopy(TINK_PREFIX, 0, out, 0, TINK_PREFIX.length);
    System.arraycopy(nonce, 0, out, TINK_PREFIX.length, nonce.length);
    System.arraycopy(ciphertext, 0, out, TINK_PREFIX.length + nonce.length, ciphertext.length);
    return out;
  }

  private static byte[] hex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  static final class Info {
    final int count;

    Info(int count) {
      this.count = count;
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
