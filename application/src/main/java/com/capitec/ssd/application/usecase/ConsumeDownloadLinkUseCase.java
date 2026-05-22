package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.port.out.*;
import com.capitec.ssd.domain.link.ConsumeResult;
import java.time.Clock;
import java.util.Map;

public class ConsumeDownloadLinkUseCase {
  private final DownloadLinkStore links;
  private final AuditLog audit;
  private final Clock clock;

  public ConsumeDownloadLinkUseCase(DownloadLinkStore links, AuditLog audit, Clock clock) {
    this.links = links;
    this.audit = audit;
    this.clock = clock;
  }

  public ConsumeResultDto execute(String token) {
    var r = links.consume(token);
    if (r instanceof ConsumeResult.Granted g) {
      audit.append(
          new AuditLog.Event(
              clock.instant(),
              AuditLog.Type.DOWNLOAD_SUCCESS,
              "public",
              null,
              g.grant().statementId().value().toString(),
              IssueDownloadLinkUseCase.sha256(token),
              Map.of()));
      return new ConsumeResultDto.Granted(g.grant().statementId(), g.grant().customerId());
    }
    audit.append(
        new AuditLog.Event(
            clock.instant(),
            AuditLog.Type.DOWNLOAD_DENIED,
            "public",
            null,
            null,
            IssueDownloadLinkUseCase.sha256(token),
            Map.of("reason", r.getClass().getSimpleName())));
    return new ConsumeResultDto.Invalid();
  }
}
