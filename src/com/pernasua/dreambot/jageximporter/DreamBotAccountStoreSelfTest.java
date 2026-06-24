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
    int actual = DreamBotAccountStore.info(db).count;
    if (actual != expected) {
      throw new AssertionError("expected " + expected + " account(s), found " + actual);
    }
  }
}
