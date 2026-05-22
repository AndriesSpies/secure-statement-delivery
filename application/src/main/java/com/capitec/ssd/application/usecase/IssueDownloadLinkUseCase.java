package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.port.out.*;
import com.capitec.ssd.domain.statement.Statement;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Map;

public class IssueDownloadLinkUseCase {
  private final StatementRepository repo;
  private final DownloadLinkStore links;
  private final TokenGenerator tokens;
  private final AuditLog audit;
  private final Clock clock;

  public IssueDownloadLinkUseCase(
      StatementRepository repo,
      DownloadLinkStore links,
      TokenGenerator tokens,
      AuditLog audit,
      Clock clock) {
    this.repo = repo;
    this.links = links;
    this.tokens = tokens;
    this.audit = audit;
    this.clock = clock;
  }

  public IssueResult execute(IssueDownloadLinkCommand cmd) {
    var maybe = repo.findById(cmd.statementId());
    if (maybe.isEmpty()) return new IssueResult.StatementNotFound();
    Statement s = maybe.get();
    if (s.status() != StatementStatus.AVAILABLE) return new IssueResult.StatementNotAvailable();

    String token = tokens.newToken();
    var exp = clock.instant().plus(cmd.ttl());
    links.create(token, s.id(), s.customerId(), exp, cmd.maxDownloads(), cmd.operator());

    audit.append(
        new AuditLog.Event(
            clock.instant(),
            AuditLog.Type.LINK_ISSUED,
            cmd.operator(),
            null,
            s.id().value().toString(),
            sha256(token),
            Map.of(
                "expiresAt", exp.toString(),
                "maxDownloads", cmd.maxDownloads())));
    return new IssueResult.Issued(token, exp);
  }

  static byte[] sha256(String s) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
