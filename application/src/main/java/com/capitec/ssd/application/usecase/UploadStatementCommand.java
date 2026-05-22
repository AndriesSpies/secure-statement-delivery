package com.capitec.ssd.application.usecase;

import com.capitec.ssd.domain.common.CustomerId;

public record UploadStatementCommand(
    CustomerId customerId, String filename, byte[] bytes, String operator) {}
