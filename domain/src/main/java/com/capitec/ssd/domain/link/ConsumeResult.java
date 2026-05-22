package com.capitec.ssd.domain.link;

public sealed interface ConsumeResult {
  record Granted(DownloadGrant grant) implements ConsumeResult {}

  record Expired() implements ConsumeResult {}

  record Exhausted() implements ConsumeResult {}

  record Revoked() implements ConsumeResult {}
}
