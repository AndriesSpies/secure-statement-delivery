package com.capitec.ssd.domain.link;

public sealed interface LinkError {
  record NotFound() implements LinkError {}

  record Expired() implements LinkError {}

  record Exhausted() implements LinkError {}

  record Revoked() implements LinkError {}
}
