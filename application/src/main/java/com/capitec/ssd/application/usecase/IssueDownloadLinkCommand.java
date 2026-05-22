package com.capitec.ssd.application.usecase;

import com.capitec.ssd.domain.common.StatementId;
import java.time.Duration;

public record IssueDownloadLinkCommand(
    StatementId statementId, Duration ttl, int maxDownloads, String operator) {}
