package com.capitec.ssd.application.crypto;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;

class AesGcmEnvelopeTest {
  @Test
  void roundtrip() {
    var env = new AesGcmEnvelope();
    byte[] dek = env.generateDek();
    byte[] pt = "hello world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] ct = env.encrypt(pt, dek);
    assertThat(ct).isNotEqualTo(pt);
    assertThat(env.decrypt(ct, dek)).isEqualTo(pt);
  }

  @Test
  void tampered_ciphertext_fails() {
    var env = new AesGcmEnvelope();
    byte[] dek = env.generateDek();
    byte[] ct = env.encrypt("x".getBytes(java.nio.charset.StandardCharsets.UTF_8), dek);
    ct[ct.length - 1] ^= 0x01;
    assertThatThrownBy(() -> env.decrypt(ct, dek)).isInstanceOf(IllegalStateException.class);
  }

  @Test
  void each_encrypt_uses_fresh_iv() {
    var env = new AesGcmEnvelope();
    byte[] dek = env.generateDek();
    byte[] ct1 = env.encrypt("x".getBytes(java.nio.charset.StandardCharsets.UTF_8), dek);
    byte[] ct2 = env.encrypt("x".getBytes(java.nio.charset.StandardCharsets.UTF_8), dek);
    assertThat(ct1).isNotEqualTo(ct2);
  }
}
