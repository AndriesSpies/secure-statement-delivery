package com.capitec.ssd.adapters.persistence;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.PostgreSQLContainer;

public final class PostgresTestcontainer {
  public static final PostgreSQLContainer<?> INSTANCE =
      new PostgreSQLContainer<>("postgres:16-alpine")
          .withDatabaseName("ssd")
          .withUsername("ssd")
          .withPassword("ssd");

  static {
    INSTANCE.start();
  }

  public static void register(DynamicPropertyRegistry r) {
    r.add("spring.datasource.url", INSTANCE::getJdbcUrl);
    r.add("spring.datasource.username", INSTANCE::getUsername);
    r.add("spring.datasource.password", INSTANCE::getPassword);
  }

  private PostgresTestcontainer() {}
}
