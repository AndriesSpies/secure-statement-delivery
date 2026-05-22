package com.capitec.ssd.application.usecase;

import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;

public sealed interface ConsumeResultDto {
  record Granted(StatementId statementId, CustomerId customerId) implements ConsumeResultDto {}

  record Invalid() implements ConsumeResultDto {}
}
