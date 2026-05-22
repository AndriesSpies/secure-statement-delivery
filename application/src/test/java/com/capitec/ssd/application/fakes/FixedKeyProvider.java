package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.crypto.WrappedDek;
import com.capitec.ssd.application.port.out.KeyProvider;

public class FixedKeyProvider implements KeyProvider {
  public String keyId = "test-kek-1";

  @Override
  public WrappedDek wrapDek(byte[] dek) {
    return new WrappedDek(dek.clone(), keyId);
  }

  @Override
  public byte[] unwrapDek(byte[] wrapped, String kid) {
    return wrapped.clone();
  }
}
