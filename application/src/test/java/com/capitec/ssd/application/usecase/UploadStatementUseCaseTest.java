package com.capitec.ssd.application.usecase;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.application.crypto.AesGcmEnvelope;
import com.capitec.ssd.application.fakes.*;
import com.capitec.ssd.application.port.out.PdfValidator;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class UploadStatementUseCaseTest {
  InMemoryStatementRepository repo;
  InMemoryObjectStorage storage;
  FixedKeyProvider keys;
  RecordingAuditLog audit;
  ScriptedPdfValidator validator;
  UploadStatementUseCase usecase;
  Clock clock;

  @BeforeEach
  void setup() {
    repo = new InMemoryStatementRepository();
    storage = new InMemoryObjectStorage();
    keys = new FixedKeyProvider();
    audit = new RecordingAuditLog();
    validator = new ScriptedPdfValidator();
    clock = Clock.fixed(Instant.parse("2026-05-22T10:00:00Z"), ZoneOffset.UTC);
    usecase =
        new UploadStatementUseCase(
            repo, storage, keys, validator, new AesGcmEnvelope(), audit, clock, 100_000);
  }

  @Test
  void happy_path_persists_quarantined_and_encrypts_object_and_audits() throws Exception {
    byte[] pdfBytes = "%PDF-1.4 stub".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    var cmd = new UploadStatementCommand(new CustomerId("c1"), "jan.pdf", pdfBytes, "op-1");

    var r = usecase.execute(cmd);

    assertThat(r).isInstanceOf(UploadResult.Accepted.class);
    var stored = repo.store.values().iterator().next();
    assertThat(stored.status()).isEqualTo(StatementStatus.QUARANTINED);
    assertThat(stored.storageKey()).startsWith("quarantine/");
    byte[] storedBlob = storage.blobs.get(stored.storageKey());
    assertThat(storedBlob).isNotEqualTo(pdfBytes);
    byte[] sha = MessageDigest.getInstance("SHA-256").digest(pdfBytes);
    assertThat(stored.sha256().bytes()).isEqualTo(sha);
    assertThat(audit.events).hasSize(1);
  }

  @Test
  void invalid_pdf_returns_InvalidPdf_and_persists_nothing() {
    validator.next = new PdfValidator.Result.Invalid("bad magic");
    var r =
        usecase.execute(
            new UploadStatementCommand(
                new CustomerId("c1"), "x.pdf", new byte[] {0, 1, 2}, "op-1"));
    assertThat(r).isInstanceOf(UploadResult.InvalidPdf.class);
    assertThat(repo.store).isEmpty();
    assertThat(storage.blobs).isEmpty();
  }

  @Test
  void over_limit_returns_TooLarge() {
    usecase =
        new UploadStatementUseCase(
            repo, storage, keys, validator, new AesGcmEnvelope(), audit, clock, 4);
    var r =
        usecase.execute(
            new UploadStatementCommand(
                new CustomerId("c1"), "x.pdf", new byte[] {1, 2, 3, 4, 5}, "op-1"));
    assertThat(r).isInstanceOf(UploadResult.TooLarge.class);
  }
}
