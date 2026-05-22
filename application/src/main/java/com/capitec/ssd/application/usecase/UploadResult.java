package com.capitec.ssd.application.usecase;

import com.capitec.ssd.domain.common.StatementId;

public sealed interface UploadResult {
  record Accepted(StatementId id) implements UploadResult {}

  record InvalidPdf(String reason) implements UploadResult {}

  record TooLarge(long bytes, long limit) implements UploadResult {}
}
