package com.capitec.ssd.application.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmEnvelope {
  public static final int IV_BYTES = 12;
  public static final int TAG_BITS = 128;
  public static final int KEY_BYTES = 32;

  private final SecureRandom random;

  public AesGcmEnvelope() {
    this(new SecureRandom());
  }

  public AesGcmEnvelope(SecureRandom random) {
    this.random = random;
  }

  public byte[] generateDek() {
    byte[] dek = new byte[KEY_BYTES];
    random.nextBytes(dek);
    return dek;
  }

  public byte[] encrypt(byte[] plaintext, byte[] dek) {
    try {
      byte[] iv = new byte[IV_BYTES];
      random.nextBytes(iv);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      byte[] ct = c.doFinal(plaintext);
      byte[] out = new byte[iv.length + ct.length];
      System.arraycopy(iv, 0, out, 0, iv.length);
      System.arraycopy(ct, 0, out, iv.length, ct.length);
      return out;
    } catch (Exception e) {
      throw new IllegalStateException("encrypt failed", e);
    }
  }

  public byte[] decrypt(byte[] ivPlusCiphertext, byte[] dek) {
    try {
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(dek, "AES"),
          new GCMParameterSpec(TAG_BITS, ivPlusCiphertext, 0, IV_BYTES));
      return c.doFinal(ivPlusCiphertext, IV_BYTES, ivPlusCiphertext.length - IV_BYTES);
    } catch (Exception e) {
      throw new IllegalStateException("decrypt failed", e);
    }
  }
}
