package com.capitec.ssd.application.usecase;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.application.crypto.AesGcmEnvelope;
import com.capitec.ssd.application.fakes.*;
import com.capitec.ssd.application.port.out.ContentScanner;
import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PromoteOrRejectStatementUseCaseTest {

  InMemoryStatementRepository repo;
  InMemoryObjectStorage storage;
  FixedKeyProvider keys;
  RecordingAuditLog audit;
  ScriptedScanner scanner;
  PromoteOrRejectStatementUseCase usecase;
  Clock clock;
  AesGcmEnvelope crypto;

  @BeforeEach
  void setup() {
    repo = new InMemoryStatementRepository();
    storage = new InMemoryObjectStorage();
    keys = new FixedKeyProvider();
    audit = new RecordingAuditLog();
    scanner = new ScriptedScanner();
    clock = Clock.fixed(Instant.parse("2026-05-22T10:00:00Z"), ZoneOffset.UTC);
    crypto = new AesGcmEnvelope();
    usecase =
        new PromoteOrRejectStatementUseCase(repo, storage, keys, scanner, crypto, audit, clock);
  }

  private Statement seedQuarantined() {
    byte[] dek = crypto.generateDek();
    byte[] ct = crypto.encrypt("%PDF stub".getBytes(java.nio.charset.StandardCharsets.UTF_8), dek);
    var wrapped = keys.wrapDek(dek);
    var id = StatementId.newId();
    String key = storage.putQuarantine(id.value().toString(), ct);
    var s =
        Statement.newQuarantined(
            id,
            new CustomerId("c1"),
            "a.pdf",
            new ByteSize(9),
            new Sha256(new byte[32]),
            MediaType.applicationPdf(),
            key,
            wrapped.ciphertext(),
            wrapped.keyId(),
            "op",
            clock.instant());
    repo.save(s);
    return s;
  }

  @Test
  void clean_scan_promotes_to_available() {
    var s = seedQuarantined();
    scanner.next = new ContentScanner.Result.Clean();
    usecase.processBatch(10);
    var after = repo.findById(s.id()).orElseThrow();
    assertThat(after.status()).isEqualTo(StatementStatus.AVAILABLE);
    assertThat(after.storageKey()).startsWith("available/");
  }

  @Test
  void infected_scan_rejects_and_deletes_object() {
    var s = seedQuarantined();
    scanner.next = new ContentScanner.Result.Infected("EICAR-Test-Signature");
    usecase.processBatch(10);
    var after = repo.findById(s.id()).orElseThrow();
    assertThat(after.status()).isEqualTo(StatementStatus.REJECTED);
    assertThat(after.rejectionReason()).contains("EICAR");
    assertThat(storage.blobs).isEmpty();
  }
}
