package com.capitec.ssd.application.port.out;

import com.capitec.ssd.application.crypto.WrappedDek;

public interface KeyProvider {
  WrappedDek wrapDek(byte[] plaintextDek);

  byte[] unwrapDek(byte[] wrappedDek, String keyId);
}
