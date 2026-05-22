package com.capitec.ssd.domain.statement;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.domain.common.*;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class StatementTest {

  private Statement newQuarantined() {
    return Statement.newQuarantined(
        StatementId.newId(),
        new CustomerId("c1"),
        "jan-2026.pdf",
        new ByteSize(1024),
        new Sha256(new byte[32]),
        MediaType.applicationPdf(),
        "quarantine/key",
        new byte[] {1, 2, 3},
        "kek-1",
        "operator-1",
        Instant.parse("2026-05-22T10:00:00Z"));
  }

  @Test
  void newly_created_statement_is_quarantined() {
    assertThat(newQuarantined().status()).isEqualTo(StatementStatus.QUARANTINED);
  }

  @Test
  void markAvailable_moves_to_available_and_updates_storage_key() {
    var s = newQuarantined();
    s.markAvailable("available/key", Instant.parse("2026-05-22T10:01:00Z"));
    assertThat(s.status()).isEqualTo(StatementStatus.AVAILABLE);
    assertThat(s.storageKey()).isEqualTo("available/key");
  }

  @Test
  void markAvailable_from_rejected_throws() {
    var s = newQuarantined();
    s.markRejected("virus:EICAR-Test", Instant.parse("2026-05-22T10:01:00Z"));
    assertThatThrownBy(() -> s.markAvailable("k", Instant.now()))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void markRejected_persists_reason() {
    var s = newQuarantined();
    s.markRejected("virus:EICAR-Test", Instant.parse("2026-05-22T10:01:00Z"));
    assertThat(s.status()).isEqualTo(StatementStatus.REJECTED);
    assertThat(s.rejectionReason()).isEqualTo("virus:EICAR-Test");
  }

  @Test
  void markDeleted_only_from_available() {
    var s = newQuarantined();
    assertThatThrownBy(() -> s.markDeleted(Instant.now()))
        .isInstanceOf(IllegalStateException.class);
    s.markAvailable("k", Instant.now());
    s.markDeleted(Instant.now());
    assertThat(s.status()).isEqualTo(StatementStatus.DELETED);
  }
}
