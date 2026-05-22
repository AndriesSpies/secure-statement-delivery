package com.capitec.ssd.application.port.out;

public interface ContentScanner {
  sealed interface Result {
    record Clean() implements Result {}

    record Infected(String signature) implements Result {}

    record Error(String message) implements Result {}
  }

  Result scan(byte[] plaintext);
}
