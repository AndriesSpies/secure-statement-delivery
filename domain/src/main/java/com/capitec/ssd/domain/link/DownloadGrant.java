package com.capitec.ssd.domain.link;

import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;

public record DownloadGrant(String token, StatementId statementId, CustomerId customerId) {}
