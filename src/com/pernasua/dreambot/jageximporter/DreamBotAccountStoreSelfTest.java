package com.pernasua.dreambot.jageximporter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

final class DreamBotAccountStoreSelfTest {
  private DreamBotAccountStoreSelfTest() {
  }

  public static void main(String[] args) throws Exception {
    Path dir = Files.createTempDirectory("dreambot-account-store-test-");
    Path db = dir.resolve("accounts.db");
    DreamBotAccountStore.BackupContext backupContext = DreamBotAccountStore.backupContext();
    try {
      DreamBotAccountStore.writeForTest(db, List.of());
      assertCount(db, 0);

      DreamBotJagexBulkImporter.AccountRow account =
          new DreamBotJagexBulkImporter.AccountRow(1, 1, "row1@example.invalid", "password", "JBSWY3DPEHPK3PXP");
      DreamBotAccountStore.AddResult result =
          DreamBotAccountStore.addLegacyAccount(db, account, null, backupContext);
      if (result.beforeCount != 0 || result.afterCount != 1 || result.addedCount != 1) {
        throw new AssertionError("unexpected add result: " + result.beforeCount + " -> "
            + result.afterCount + ", added " + result.addedCount);
      }
      assertCount(db, 1);

      DreamBotAccountStore.writeForTest(db, List.of(Map.of("nickname", "existing", "username", "existing")));
      assertCount(db, 1);

      DreamBotAccountStore.writeForTest(db,
          List.of(Map.of("nickname", "new-aad", "username", "new-aad")), 256615);
      assertInfo(db, 1, 256615);
    } finally {
      Files.deleteIfExists(db);
      Files.deleteIfExists(dir.resolve("accounts.db.lock"));
      if (backupContext.path() != null) {
        Files.deleteIfExists(backupContext.path());
      }
      Files.deleteIfExists(dir);
    }
  }

  private static void assertCount(Path db, int expected) throws Exception {
    assertInfo(db, expected, null);
  }

  private static void assertInfo(Path db, int expectedCount, Integer expectedAad) throws Exception {
    DreamBotAccountStore.Info info = DreamBotAccountStore.info(db);
    int actual = info.count;
    if (actual != expectedCount) {
      throw new AssertionError("expected " + expectedCount + " account(s), found " + actual);
    }
    if (expectedAad != null && !expectedAad.equals(info.aad)) {
      throw new AssertionError("expected AAD " + expectedAad + ", found " + info.aad);
    }
  }
}
