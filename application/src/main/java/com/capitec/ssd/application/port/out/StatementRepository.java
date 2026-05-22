package com.capitec.ssd.application.port.out;

import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import java.util.List;
import java.util.Optional;

public interface StatementRepository {
  void save(Statement s);

  Optional<Statement> findById(StatementId id);

  List<Statement> findQuarantinedBatch(int limit);

  List<Statement> findByCustomer(CustomerId customer, int limit, int offset);
}
