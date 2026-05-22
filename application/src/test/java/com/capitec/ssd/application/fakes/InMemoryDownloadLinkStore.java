package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.DownloadLinkStore;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.link.ConsumeResult;
import com.capitec.ssd.domain.link.DownloadLink;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public class InMemoryDownloadLinkStore implements DownloadLinkStore {
  public Clock clock = Clock.systemUTC();
  public final Map<String, DownloadLink> store = new LinkedHashMap<>();

  @Override
  public void create(
      String token, StatementId sid, CustomerId cid, Instant exp, int max, String by) {
    store.put(token, DownloadLink.issue(token, sid, cid, exp, max, clock.instant(), by));
  }

  @Override
  public synchronized ConsumeResult consume(String token) {
    var l = store.get(token);
    if (l == null) return new ConsumeResult.Expired();
    return l.consume(clock);
  }

  @Override
  public synchronized boolean revoke(String token) {
    var l = store.get(token);
    if (l == null) return false;
    l.revoke(clock.instant());
    return true;
  }
}
