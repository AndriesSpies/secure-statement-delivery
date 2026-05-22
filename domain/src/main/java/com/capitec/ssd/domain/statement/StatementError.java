package com.capitec.ssd.domain.statement;

public sealed interface StatementError {
  record NotFound(String id) implements StatementError {}

  record NotAvailable(String id, StatementStatus actual) implements StatementError {}

  record AlreadyExists(String id) implements StatementError {}
}
