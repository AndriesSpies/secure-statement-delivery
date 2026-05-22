package com.capitec.ssd.domain.common;

import java.util.Objects;

public record MediaType(String value) {
  public static final String APPLICATION_PDF = "application/pdf";

  public MediaType {
    Objects.requireNonNull(value, "value");
    if (!APPLICATION_PDF.equals(value)) {
      throw new IllegalArgumentException("Only application/pdf is supported");
    }
  }

  public static MediaType applicationPdf() {
    return new MediaType(APPLICATION_PDF);
  }

  public static MediaType of(String v) {
    return new MediaType(v);
  }
}
