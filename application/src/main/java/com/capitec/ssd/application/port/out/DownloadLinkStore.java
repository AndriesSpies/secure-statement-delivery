package com.capitec.ssd.application.port.out;

import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.link.ConsumeResult;
import java.time.Instant;

public interface DownloadLinkStore {
  void create(
      String token,
      StatementId statementId,
      CustomerId customerId,
      Instant expiresAt,
      int maxDownloads,
      String createdBy);

  ConsumeResult consume(String token);

  boolean revoke(String token);
}
