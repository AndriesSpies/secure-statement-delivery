package com.capitec.ssd.application.usecase;

import static org.assertj.core.api.Assertions.*;

import com.capitec.ssd.application.fakes.InMemoryStatementRepository;
import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ListStatementsForCustomerUseCaseTest {

  @Test
  void filters_by_customer_and_pages() {
    var repo = new InMemoryStatementRepository();
    var now = Instant.parse("2026-05-22T10:00:00Z");
    for (int i = 0; i < 3; i++) repo.save(stub("c1", "a" + i, now));
    for (int i = 0; i < 2; i++) repo.save(stub("c2", "b" + i, now));

    var uc = new ListStatementsForCustomerUseCase(repo);
    var page = uc.execute(new CustomerId("c1"), 10, 0);
    assertThat(page).hasSize(3);
  }

  private static Statement stub(String c, String name, Instant now) {
    return Statement.newQuarantined(
        StatementId.newId(),
        new CustomerId(c),
        name + ".pdf",
        new ByteSize(1),
        new Sha256(new byte[32]),
        MediaType.applicationPdf(),
        "k",
        new byte[] {0},
        "k1",
        "op",
        now);
  }
}
