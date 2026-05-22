package com.capitec.ssd.domain.link;

import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

public final class DownloadLink {
  private final String token;
  private final StatementId statementId;
  private final CustomerId customerId;
  private final Instant expiresAt;
  private final int maxDownloads;
  private int remainingDownloads;
  private @Nullable Instant revokedAt;
  private final Instant createdAt;
  private final String createdBy;

  private DownloadLink(
      String token,
      StatementId statementId,
      CustomerId customerId,
      Instant expiresAt,
      int maxDownloads,
      int remainingDownloads,
      @Nullable Instant revokedAt,
      Instant createdAt,
      String createdBy) {
    this.token = token;
    this.statementId = statementId;
    this.customerId = customerId;
    this.expiresAt = expiresAt;
    this.maxDownloads = maxDownloads;
    this.remainingDownloads = remainingDownloads;
    this.revokedAt = revokedAt;
    this.createdAt = createdAt;
    this.createdBy = createdBy;
  }

  public static DownloadLink issue(
      String token,
      StatementId statementId,
      CustomerId customerId,
      Instant expiresAt,
      int maxDownloads,
      Instant now,
      String createdBy) {
    Objects.requireNonNull(token);
    Objects.requireNonNull(statementId);
    Objects.requireNonNull(customerId);
    Objects.requireNonNull(expiresAt);
    if (maxDownloads <= 0) throw new IllegalArgumentException("maxDownloads must be > 0");
    if (!expiresAt.isAfter(now)) throw new IllegalArgumentException("expiresAt must be future");
    return new DownloadLink(
        token,
        statementId,
        customerId,
        expiresAt,
        maxDownloads,
        maxDownloads,
        null,
        now,
        createdBy);
  }

  public static DownloadLink rehydrate(
      String token,
      StatementId statementId,
      CustomerId customerId,
      Instant expiresAt,
      int maxDownloads,
      int remainingDownloads,
      @Nullable Instant revokedAt,
      Instant createdAt,
      String createdBy) {
    return new DownloadLink(
        token,
        statementId,
        customerId,
        expiresAt,
        maxDownloads,
        remainingDownloads,
        revokedAt,
        createdAt,
        createdBy);
  }

  public ConsumeResult consume(Clock clock) {
    Instant now = clock.instant();
    if (revokedAt != null) return new ConsumeResult.Revoked();
    if (!now.isBefore(expiresAt)) return new ConsumeResult.Expired();
    if (remainingDownloads <= 0) return new ConsumeResult.Exhausted();
    remainingDownloads--;
    return new ConsumeResult.Granted(new DownloadGrant(token, statementId, customerId));
  }

  public void revoke(Instant now) {
    if (revokedAt == null) this.revokedAt = now;
  }

  public String token() {
    return token;
  }

  public StatementId statementId() {
    return statementId;
  }

  public CustomerId customerId() {
    return customerId;
  }

  public Instant expiresAt() {
    return expiresAt;
  }

  public int maxDownloads() {
    return maxDownloads;
  }

  public int remainingDownloads() {
    return remainingDownloads;
  }

  public @Nullable Instant revokedAt() {
    return revokedAt;
  }

  public Instant createdAt() {
    return createdAt;
  }

  public String createdBy() {
    return createdBy;
  }
}
