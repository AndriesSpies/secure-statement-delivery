package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.AuditLog;
import java.util.ArrayList;
import java.util.List;

public class RecordingAuditLog implements AuditLog {
  public final List<Event> events = new ArrayList<>();

  @Override
  public void append(Event e) {
    events.add(e);
  }
}
