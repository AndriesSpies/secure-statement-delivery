package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.TokenGenerator;
import java.util.concurrent.atomic.AtomicInteger;

public class CountingTokenGenerator implements TokenGenerator {
  private final AtomicInteger n = new AtomicInteger();

  @Override
  public String newToken() {
    return "tok-" + n.incrementAndGet();
  }
}
