package com.capitec.ssd.application.usecase;

import java.time.Instant;

public sealed interface IssueResult {
  record Issued(String token, Instant expiresAt) implements IssueResult {}

  record StatementNotFound() implements IssueResult {}

  record StatementNotAvailable() implements IssueResult {}
}
