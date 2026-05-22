package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.crypto.AesGcmEnvelope;
import com.capitec.ssd.application.port.out.*;
import com.capitec.ssd.domain.statement.Statement;
import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.util.Map;

public class PromoteOrRejectStatementUseCase {
  private final StatementRepository repo;
  private final ObjectStorageGateway storage;
  private final KeyProvider keys;
  private final ContentScanner scanner;
  private final AesGcmEnvelope crypto;
  private final AuditLog audit;
  private final Clock clock;

  public PromoteOrRejectStatementUseCase(
      StatementRepository repo,
      ObjectStorageGateway storage,
      KeyProvider keys,
      ContentScanner scanner,
      AesGcmEnvelope crypto,
      AuditLog audit,
      Clock clock) {
    this.repo = repo;
    this.storage = storage;
    this.keys = keys;
    this.scanner = scanner;
    this.crypto = crypto;
    this.audit = audit;
    this.clock = clock;
  }

  public void processBatch(int limit) {
    for (Statement s : repo.findQuarantinedBatch(limit)) processOne(s);
  }

  private void processOne(Statement s) {
    byte[] ciphertext;
    try (InputStream in = storage.openStream(s.storageKey())) {
      ciphertext = in.readAllBytes();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    byte[] dek = keys.unwrapDek(s.encryptedDek(), s.dekKeyId());
    byte[] plaintext = crypto.decrypt(ciphertext, dek);

    var result = scanner.scan(plaintext);
    if (result instanceof ContentScanner.Result.Clean) {
      String available = storage.promote(s.storageKey());
      s.markAvailable(available, clock.instant());
      repo.save(s);
      audit.append(
          new AuditLog.Event(
              clock.instant(),
              AuditLog.Type.SCAN_PASSED,
              "system",
              null,
              s.id().value().toString(),
              null,
              Map.of()));
    } else if (result instanceof ContentScanner.Result.Infected i) {
      storage.delete(s.storageKey());
      s.markRejected("virus:" + i.signature(), clock.instant());
      repo.save(s);
      audit.append(
          new AuditLog.Event(
              clock.instant(),
              AuditLog.Type.SCAN_REJECTED,
              "system",
              null,
              s.id().value().toString(),
              null,
              Map.of("signature", i.signature())));
    }
  }
}
