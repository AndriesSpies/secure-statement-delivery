package com.capitec.ssd.adapters.persistence;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaStatementRepository.class)
class JpaStatementRepositoryIT {

  @DynamicPropertySource
  static void props(DynamicPropertyRegistry r) {
    PostgresTestcontainer.register(r);
  }

  @Autowired JpaStatementRepository repo;

  @Test
  void roundtrip_and_quarantined_query() {
    var s =
        Statement.newQuarantined(
            StatementId.newId(),
            new CustomerId("c1"),
            "a.pdf",
            new ByteSize(10),
            new Sha256(new byte[32]),
            MediaType.applicationPdf(),
            "quarantine/k",
            new byte[] {1, 2, 3},
            "kek-1",
            "op",
            Instant.parse("2026-05-22T10:00:00Z"));
    repo.save(s);
    var found = repo.findById(s.id()).orElseThrow();
    assertThat(found.status()).isEqualTo(StatementStatus.QUARANTINED);
    assertThat(repo.findQuarantinedBatch(10)).hasSize(1);
  }
}
