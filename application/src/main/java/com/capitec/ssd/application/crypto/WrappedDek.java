package com.capitec.ssd.application.crypto;

public record WrappedDek(byte[] ciphertext, String keyId) {}
