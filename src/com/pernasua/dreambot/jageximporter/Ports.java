package com.pernasua.dreambot.jageximporter;

import java.io.IOException;
import java.net.ServerSocket;

final class Ports {
  private Ports() {
  }

  static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      socket.setReuseAddress(true);
      return socket.getLocalPort();
    }
  }
}
