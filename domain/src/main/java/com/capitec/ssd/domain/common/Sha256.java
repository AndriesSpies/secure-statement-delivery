package com.capitec.ssd.domain.common;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

public final class Sha256 {
  public static final int BYTES = 32;
  private final byte[] bytes;

  public Sha256(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length != BYTES) throw new IllegalArgumentException("SHA-256 must be 32 bytes");
    this.bytes = bytes.clone();
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  public String hex() {
    return HexFormat.of().formatHex(bytes);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Sha256 s && Arrays.equals(bytes, s.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "Sha256[" + hex() + "]";
  }
}
