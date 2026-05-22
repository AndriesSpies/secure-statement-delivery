package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.StatementRepository;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class InMemoryStatementRepository implements StatementRepository {
  public final Map<StatementId, Statement> store = new LinkedHashMap<>();

  @Override
  public void save(Statement s) {
    store.put(s.id(), s);
  }

  @Override
  public Optional<Statement> findById(StatementId id) {
    return Optional.ofNullable(store.get(id));
  }

  @Override
  public List<Statement> findQuarantinedBatch(int limit) {
    return store.values().stream()
        .filter(s -> s.status() == StatementStatus.QUARANTINED)
        .limit(limit)
        .collect(Collectors.toList());
  }

  @Override
  public List<Statement> findByCustomer(CustomerId customer, int limit, int offset) {
    return store.values().stream()
        .filter(s -> s.customerId().equals(customer))
        .skip(offset)
        .limit(limit)
        .collect(Collectors.toList());
  }
}
