package com.capitec.ssd.application.usecase;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.application.fakes.*;
import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LinkUseCasesTest {

  InMemoryStatementRepository repo;
  InMemoryDownloadLinkStore links;
  CountingTokenGenerator tokens;
  RecordingAuditLog audit;
  Clock clock;
  IssueDownloadLinkUseCase issue;
  ConsumeDownloadLinkUseCase consume;
  RevokeDownloadLinkUseCase revoke;

  @BeforeEach
  void setup() {
    repo = new InMemoryStatementRepository();
    links = new InMemoryDownloadLinkStore();
    tokens = new CountingTokenGenerator();
    audit = new RecordingAuditLog();
    clock = Clock.fixed(Instant.parse("2026-05-22T10:00:00Z"), ZoneOffset.UTC);
    links.clock = clock;
    issue = new IssueDownloadLinkUseCase(repo, links, tokens, audit, clock);
    consume = new ConsumeDownloadLinkUseCase(links, audit, clock);
    revoke = new RevokeDownloadLinkUseCase(links, audit, clock);
  }

  private Statement seedAvailable() {
    var s =
        Statement.newQuarantined(
            StatementId.newId(),
            new CustomerId("c1"),
            "a.pdf",
            new ByteSize(10),
            new Sha256(new byte[32]),
            MediaType.applicationPdf(),
            "available/k",
            new byte[] {1},
            "k",
            "op",
            clock.instant());
    s.markAvailable("available/k", clock.instant());
    repo.save(s);
    return s;
  }

  @Test
  void issue_then_consume_grants_once_and_then_404() {
    var s = seedAvailable();
    var r = issue.execute(new IssueDownloadLinkCommand(s.id(), Duration.ofMinutes(5), 1, "op"));
    assertThat(r).isInstanceOf(IssueResult.Issued.class);
    var tok = ((IssueResult.Issued) r).token();
    assertThat(consume.execute(tok)).isInstanceOf(ConsumeResultDto.Granted.class);
    assertThat(consume.execute(tok)).isInstanceOf(ConsumeResultDto.Invalid.class);
  }

  @Test
  void issue_for_non_available_returns_StatementNotAvailable() {
    var s =
        Statement.newQuarantined(
            StatementId.newId(),
            new CustomerId("c1"),
            "a.pdf",
            new ByteSize(10),
            new Sha256(new byte[32]),
            MediaType.applicationPdf(),
            "quarantine/k",
            new byte[] {1},
            "k",
            "op",
            clock.instant());
    repo.save(s);
    var r = issue.execute(new IssueDownloadLinkCommand(s.id(), Duration.ofMinutes(5), 1, "op"));
    assertThat(r).isInstanceOf(IssueResult.StatementNotAvailable.class);
  }

  @Test
  void issue_for_missing_returns_StatementNotFound() {
    var r =
        issue.execute(
            new IssueDownloadLinkCommand(StatementId.newId(), Duration.ofMinutes(5), 1, "op"));
    assertThat(r).isInstanceOf(IssueResult.StatementNotFound.class);
  }

  @Test
  void revoke_then_consume_invalid() {
    var s = seedAvailable();
    var iss =
        (IssueResult.Issued)
            issue.execute(new IssueDownloadLinkCommand(s.id(), Duration.ofMinutes(5), 3, "op"));
    assertThat(revoke.execute(iss.token())).isTrue();
    assertThat(consume.execute(iss.token())).isInstanceOf(ConsumeResultDto.Invalid.class);
  }
}
