package com.capitec.ssd.domain.statement;

import com.capitec.ssd.domain.common.*;
import java.time.Instant;
import java.util.Objects;

@SuppressWarnings("NullAway")
public final class Statement {
  private final StatementId id;
  private final CustomerId customerId;
  private final String filename;
  private final ByteSize size;
  private final Sha256 sha256;
  private final MediaType mediaType;
  private String storageKey;
  private final byte[] encryptedDek;
  private final String dekKeyId;
  private final String createdBy;
  private final Instant createdAt;
  private StatementStatus status;
  private String rejectionReason;
  private Instant updatedAt;

  private Statement(
      StatementId id,
      CustomerId customerId,
      String filename,
      ByteSize size,
      Sha256 sha256,
      MediaType mediaType,
      String storageKey,
      byte[] encryptedDek,
      String dekKeyId,
      String createdBy,
      Instant createdAt,
      StatementStatus status,
      String rejectionReason,
      Instant updatedAt) {
    this.id = id;
    this.customerId = customerId;
    this.filename = filename;
    this.size = size;
    this.sha256 = sha256;
    this.mediaType = mediaType;
    this.storageKey = storageKey;
    this.encryptedDek = encryptedDek.clone();
    this.dekKeyId = dekKeyId;
    this.createdBy = createdBy;
    this.createdAt = createdAt;
    this.status = status;
    this.rejectionReason = rejectionReason;
    this.updatedAt = updatedAt;
  }

  public static Statement newQuarantined(
      StatementId id,
      CustomerId customerId,
      String filename,
      ByteSize size,
      Sha256 sha256,
      MediaType mediaType,
      String storageKey,
      byte[] encryptedDek,
      String dekKeyId,
      String createdBy,
      Instant now) {
    Objects.requireNonNull(filename);
    if (filename.isBlank()) throw new IllegalArgumentException("filename blank");
    return new Statement(
        id,
        customerId,
        filename,
        size,
        sha256,
        mediaType,
        storageKey,
        encryptedDek,
        dekKeyId,
        createdBy,
        now,
        StatementStatus.QUARANTINED,
        null,
        now);
  }

  public static Statement rehydrate(
      StatementId id,
      CustomerId customerId,
      String filename,
      ByteSize size,
      Sha256 sha256,
      MediaType mediaType,
      String storageKey,
      byte[] encryptedDek,
      String dekKeyId,
      String createdBy,
      Instant createdAt,
      StatementStatus status,
      String rejectionReason,
      Instant updatedAt) {
    return new Statement(
        id,
        customerId,
        filename,
        size,
        sha256,
        mediaType,
        storageKey,
        encryptedDek,
        dekKeyId,
        createdBy,
        createdAt,
        status,
        rejectionReason,
        updatedAt);
  }

  public void markAvailable(String newStorageKey, Instant now) {
    if (status != StatementStatus.QUARANTINED)
      throw new IllegalStateException("markAvailable requires QUARANTINED, was " + status);
    this.storageKey = Objects.requireNonNull(newStorageKey);
    this.status = StatementStatus.AVAILABLE;
    this.updatedAt = now;
  }

  public void markRejected(String reason, Instant now) {
    if (status != StatementStatus.QUARANTINED)
      throw new IllegalStateException("markRejected requires QUARANTINED, was " + status);
    this.rejectionReason = Objects.requireNonNull(reason);
    this.status = StatementStatus.REJECTED;
    this.updatedAt = now;
  }

  public void markDeleted(Instant now) {
    if (status != StatementStatus.AVAILABLE)
      throw new IllegalStateException("markDeleted requires AVAILABLE, was " + status);
    this.status = StatementStatus.DELETED;
    this.updatedAt = now;
  }

  public StatementId id() {
    return id;
  }

  public CustomerId customerId() {
    return customerId;
  }

  public String filename() {
    return filename;
  }

  public ByteSize size() {
    return size;
  }

  public Sha256 sha256() {
    return sha256;
  }

  public MediaType mediaType() {
    return mediaType;
  }

  public String storageKey() {
    return storageKey;
  }

  public byte[] encryptedDek() {
    return encryptedDek.clone();
  }

  public String dekKeyId() {
    return dekKeyId;
  }

  public String createdBy() {
    return createdBy;
  }

  public Instant createdAt() {
    return createdAt;
  }

  public StatementStatus status() {
    return status;
  }

  public String rejectionReason() {
    return rejectionReason;
  }

  public Instant updatedAt() {
    return updatedAt;
  }
}
