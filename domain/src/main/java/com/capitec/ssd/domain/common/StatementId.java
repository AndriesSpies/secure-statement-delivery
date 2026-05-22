package com.capitec.ssd.domain.common;

import java.util.Objects;
import java.util.UUID;

public record StatementId(UUID value) {
  public StatementId {
    Objects.requireNonNull(value, "value");
  }

  public static StatementId newId() {
    return new StatementId(UUID.randomUUID());
  }

  public static StatementId of(UUID v) {
    return new StatementId(v);
  }
}
