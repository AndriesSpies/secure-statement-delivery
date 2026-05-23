package com.capitec.ssd.adapters.persistence;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "statement")
@SuppressWarnings("NullAway.Init") // JPA hydrates fields via reflection after no-arg ctor
public class StatementEntity {
  @Id private UUID id;

  @Column(name = "customer_id", nullable = false)
  private String customerId;

  @Column(nullable = false)
  private String filename;

  @Column(name = "size_bytes", nullable = false)
  private long sizeBytes;

  @Column(name = "media_type", nullable = false)
  private String mediaType;

  @Column(nullable = false)
  private byte[] sha256;

  @Column(nullable = false)
  private String status;

  @Column(name = "rejection_reason")
  private @Nullable String rejectionReason;

  @Column(name = "storage_key", nullable = false)
  private String storageKey;

  @Column(name = "encrypted_dek", nullable = false)
  private byte[] encryptedDek;

  @Column(name = "dek_key_id", nullable = false)
  private String dekKeyId;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @Column(name = "created_by", nullable = false)
  private String createdBy;

  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  protected StatementEntity() {}

  public UUID getId() {
    return id;
  }

  public void setId(UUID v) {
    id = v;
  }

  public String getCustomerId() {
    return customerId;
  }

  public void setCustomerId(String v) {
    customerId = v;
  }

  public String getFilename() {
    return filename;
  }

  public void setFilename(String v) {
    filename = v;
  }

  public long getSizeBytes() {
    return sizeBytes;
  }

  public void setSizeBytes(long v) {
    sizeBytes = v;
  }

  public String getMediaType() {
    return mediaType;
  }

  public void setMediaType(String v) {
    mediaType = v;
  }

  public byte[] getSha256() {
    return sha256;
  }

  public void setSha256(byte[] v) {
    sha256 = v;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String v) {
    status = v;
  }

  public @Nullable String getRejectionReason() {
    return rejectionReason;
  }

  public void setRejectionReason(@Nullable String v) {
    rejectionReason = v;
  }

  public String getStorageKey() {
    return storageKey;
  }

  public void setStorageKey(String v) {
    storageKey = v;
  }

  public byte[] getEncryptedDek() {
    return encryptedDek;
  }

  public void setEncryptedDek(byte[] v) {
    encryptedDek = v;
  }

  public String getDekKeyId() {
    return dekKeyId;
  }

  public void setDekKeyId(String v) {
    dekKeyId = v;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(Instant v) {
    createdAt = v;
  }

  public String getCreatedBy() {
    return createdBy;
  }

  public void setCreatedBy(String v) {
    createdBy = v;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(Instant v) {
    updatedAt = v;
  }
}
