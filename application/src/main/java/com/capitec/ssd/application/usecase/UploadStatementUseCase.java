package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.crypto.AesGcmEnvelope;
import com.capitec.ssd.application.crypto.WrappedDek;
import com.capitec.ssd.application.port.out.*;
import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Map;

public class UploadStatementUseCase {
  private final StatementRepository repo;
  private final ObjectStorageGateway storage;
  private final KeyProvider keys;
  private final PdfValidator validator;
  private final AesGcmEnvelope crypto;
  private final AuditLog audit;
  private final Clock clock;
  private final long maxBytes;

  public UploadStatementUseCase(
      StatementRepository repo,
      ObjectStorageGateway storage,
      KeyProvider keys,
      PdfValidator validator,
      AesGcmEnvelope crypto,
      AuditLog audit,
      Clock clock,
      long maxBytes) {
    this.repo = repo;
    this.storage = storage;
    this.keys = keys;
    this.validator = validator;
    this.crypto = crypto;
    this.audit = audit;
    this.clock = clock;
    this.maxBytes = maxBytes;
  }

  public UploadResult execute(UploadStatementCommand cmd) {
    if (cmd.bytes().length > maxBytes)
      return new UploadResult.TooLarge(cmd.bytes().length, maxBytes);
    var validation = validator.validate(cmd.bytes());
    if (validation instanceof PdfValidator.Result.Invalid inv)
      return new UploadResult.InvalidPdf(inv.reason());

    byte[] sha = sha256(cmd.bytes());
    byte[] dek = crypto.generateDek();
    WrappedDek wrapped = keys.wrapDek(dek);
    byte[] ciphertext = crypto.encrypt(cmd.bytes(), dek);

    StatementId id = StatementId.newId();
    String key = storage.putQuarantine(id.value().toString(), ciphertext);
    var statement =
        Statement.newQuarantined(
            id,
            cmd.customerId(),
            cmd.filename(),
            new ByteSize(cmd.bytes().length),
            new Sha256(sha),
            MediaType.applicationPdf(),
            key,
            wrapped.ciphertext(),
            wrapped.keyId(),
            cmd.operator(),
            clock.instant());
    repo.save(statement);

    audit.append(
        new AuditLog.Event(
            clock.instant(),
            AuditLog.Type.UPLOADED,
            cmd.operator(),
            null,
            id.value().toString(),
            null,
            Map.of("filename", cmd.filename(), "size", cmd.bytes().length)));
    return new UploadResult.Accepted(id);
  }

  private static byte[] sha256(byte[] in) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(in);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
