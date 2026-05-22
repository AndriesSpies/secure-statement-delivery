package com.capitec.ssd.domain.common;

public record CustomerId(String value) {
  public CustomerId {
    if (value == null) throw new IllegalArgumentException("CustomerId null");
    String trimmed = value.strip();
    if (trimmed.isEmpty()) throw new IllegalArgumentException("CustomerId blank");
    if (trimmed.length() > 64) throw new IllegalArgumentException("CustomerId too long");
    value = trimmed;
  }
}
