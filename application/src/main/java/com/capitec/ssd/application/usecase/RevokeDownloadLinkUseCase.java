package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.port.out.*;
import java.time.Clock;
import java.util.Map;

public class RevokeDownloadLinkUseCase {
  private final DownloadLinkStore links;
  private final AuditLog audit;
  private final Clock clock;

  public RevokeDownloadLinkUseCase(DownloadLinkStore links, AuditLog audit, Clock clock) {
    this.links = links;
    this.audit = audit;
    this.clock = clock;
  }

  public boolean execute(String token) {
    boolean ok = links.revoke(token);
    if (ok)
      audit.append(
          new AuditLog.Event(
              clock.instant(),
              AuditLog.Type.LINK_REVOKED,
              "operator",
              null,
              null,
              IssueDownloadLinkUseCase.sha256(token),
              Map.of()));
    return ok;
  }
}
