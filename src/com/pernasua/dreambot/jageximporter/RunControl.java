package com.pernasua.dreambot.jageximporter;

import java.util.concurrent.CancellationException;

interface RunControl {
  RunControl NONE = new RunControl() { };

  default void checkpoint() {
  }

  default void sleep(long millis) {
    long deadline = System.currentTimeMillis() + Math.max(0L, millis);
    while (System.currentTimeMillis() < deadline) {
      checkpoint();
      long remaining = deadline - System.currentTimeMillis();
      try {
        Thread.sleep(Math.min(250L, Math.max(1L, remaining)));
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new CancellationException("interrupted");
      }
    }
    checkpoint();
  }
}
