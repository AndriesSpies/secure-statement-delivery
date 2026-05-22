package com.capitec.ssd.application.port.out;

import java.io.InputStream;

public interface ObjectStorageGateway {
  String putQuarantine(String key, byte[] ciphertext);

  String promote(String quarantineKey);

  InputStream openStream(String key);

  void delete(String key);
}
