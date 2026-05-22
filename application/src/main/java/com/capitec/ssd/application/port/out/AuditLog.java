package com.capitec.ssd.application.port.out;

import java.time.Instant;
import java.util.Map;

public interface AuditLog {
  enum Type {
    UPLOADED,
    SCAN_PASSED,
    SCAN_REJECTED,
    LINK_ISSUED,
    LINK_REVOKED,
    DOWNLOAD_SUCCESS,
    DOWNLOAD_DENIED
  }

  record Event(
      Instant at,
      Type type,
      String actor,
      String actorIp,
      String statementId,
      byte[] linkTokenHash,
      Map<String, Object> detail) {}

  void append(Event e);
}
