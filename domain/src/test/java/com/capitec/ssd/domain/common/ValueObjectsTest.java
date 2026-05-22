package com.capitec.ssd.domain.common;

import static org.assertj.core.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class ValueObjectsTest {

  @Test
  @SuppressWarnings("NullAway")
  void customerId_rejects_blank() {
    assertThatThrownBy(() -> new CustomerId("")).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new CustomerId(" ")).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new CustomerId(null)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void customerId_caps_length_at_64() {
    assertThatThrownBy(() -> new CustomerId("x".repeat(65)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(new CustomerId("x".repeat(64)).value()).hasSize(64);
  }

  @Test
  void statementId_random_is_unique_uuid_v4() {
    var a = StatementId.newId();
    var b = StatementId.newId();
    assertThat(a).isNotEqualTo(b);
    assertThat(a.value().version()).isEqualTo(4);
  }

  @Test
  void sha256_requires_exactly_32_bytes() {
    assertThatThrownBy(() -> new Sha256(new byte[31])).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Sha256(new byte[33])).isInstanceOf(IllegalArgumentException.class);
    var hash = new Sha256(new byte[32]);
    assertThat(hash.hex()).isEqualTo("0".repeat(64));
  }

  @Test
  void sha256_hex_roundtrip() {
    byte[] raw = HexFormat.of().parseHex("a".repeat(64));
    assertThat(new Sha256(raw).hex()).isEqualTo("a".repeat(64));
  }

  @Test
  void mediaType_only_accepts_application_pdf() {
    assertThat(MediaType.applicationPdf().value()).isEqualTo("application/pdf");
    assertThatThrownBy(() -> MediaType.of("text/plain"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void byteSize_rejects_non_positive() {
    assertThatThrownBy(() -> new ByteSize(0)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ByteSize(-1)).isInstanceOf(IllegalArgumentException.class);
    assertThat(new ByteSize(42).bytes()).isEqualTo(42L);
  }
}
