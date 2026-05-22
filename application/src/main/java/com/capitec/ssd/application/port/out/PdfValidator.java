package com.capitec.ssd.application.port.out;

public interface PdfValidator {
  sealed interface Result {
    record Valid() implements Result {}

    record Invalid(String reason) implements Result {}
  }

  Result validate(byte[] bytes);
}
