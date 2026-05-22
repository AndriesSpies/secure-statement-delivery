package com.capitec.ssd.domain.link;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.domain.common.*;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

class DownloadLinkTest {

  private static final Instant T0 = Instant.parse("2026-05-22T10:00:00Z");
  private static final Clock AT_T0 = Clock.fixed(T0, ZoneOffset.UTC);

  private DownloadLink link(int max, int remaining, Instant exp, @Nullable Instant revoked) {
    return DownloadLink.rehydrate(
        "tok",
        StatementId.of(UUID.randomUUID()),
        new CustomerId("c1"),
        exp,
        max,
        remaining,
        revoked,
        T0,
        "op");
  }

  @Test
  void consume_clean_grants_and_decrements() {
    var l = link(2, 2, T0.plusSeconds(60), null);
    ConsumeResult r = l.consume(AT_T0);
    assertThat(r).isInstanceOf(ConsumeResult.Granted.class);
    assertThat(l.remainingDownloads()).isEqualTo(1);
  }

  @Test
  void consume_expired_returns_expired() {
    var l = link(1, 1, T0.minusSeconds(1), null);
    assertThat(l.consume(AT_T0)).isInstanceOf(ConsumeResult.Expired.class);
  }

  @Test
  void consume_zero_remaining_returns_exhausted() {
    var l = link(1, 0, T0.plusSeconds(60), null);
    assertThat(l.consume(AT_T0)).isInstanceOf(ConsumeResult.Exhausted.class);
  }

  @Test
  void consume_revoked_returns_revoked() {
    var l = link(1, 1, T0.plusSeconds(60), T0.minusSeconds(1));
    assertThat(l.consume(AT_T0)).isInstanceOf(ConsumeResult.Revoked.class);
  }

  @Test
  void revoke_sets_revoked_at_and_consume_then_fails() {
    var l = link(1, 1, T0.plusSeconds(60), null);
    l.revoke(T0);
    assertThat(l.consume(AT_T0)).isInstanceOf(ConsumeResult.Revoked.class);
  }
}
