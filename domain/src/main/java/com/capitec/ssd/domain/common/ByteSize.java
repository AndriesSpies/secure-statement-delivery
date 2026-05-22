package com.capitec.ssd.domain.common;

public record ByteSize(long bytes) {
  public ByteSize {
    if (bytes <= 0) throw new IllegalArgumentException("bytes must be > 0");
  }
}
