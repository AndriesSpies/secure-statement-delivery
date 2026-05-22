package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.ObjectStorageGateway;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;

public class InMemoryObjectStorage implements ObjectStorageGateway {
  public final Map<String, byte[]> blobs = new LinkedHashMap<>();

  @Override
  public String putQuarantine(String key, byte[] ct) {
    blobs.put("quarantine/" + key, ct);
    return "quarantine/" + key;
  }

  @Override
  public String promote(String quarantineKey) {
    String tail = quarantineKey.substring("quarantine/".length());
    blobs.put("available/" + tail, blobs.remove(quarantineKey));
    return "available/" + tail;
  }

  @Override
  public InputStream openStream(String key) {
    byte[] b = blobs.get(key);
    if (b == null) throw new NoSuchElementException(key);
    return new ByteArrayInputStream(b);
  }

  @Override
  public void delete(String key) {
    blobs.remove(key);
  }
}
