package com.capitec.ssd.application.usecase;

import com.capitec.ssd.application.port.out.StatementRepository;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.statement.Statement;
import java.util.List;

public class ListStatementsForCustomerUseCase {
  private final StatementRepository repo;

  public ListStatementsForCustomerUseCase(StatementRepository repo) {
    this.repo = repo;
  }

  public List<Statement> execute(CustomerId customer, int limit, int offset) {
    return repo.findByCustomer(customer, limit, offset);
  }
}
