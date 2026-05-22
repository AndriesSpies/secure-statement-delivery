package com.capitec.ssd.adapters;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SecureStatementDeliveryApplicationTest {
  @Test
  void main_class_is_annotated() {
    assertThat(
            SecureStatementDeliveryApplication.class.isAnnotationPresent(
                org.springframework.boot.autoconfigure.SpringBootApplication.class))
        .isTrue();
  }
}
