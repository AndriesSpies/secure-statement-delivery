package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.ContentScanner;

public class ScriptedScanner implements ContentScanner {
  public Result next = new Result.Clean();

  @Override
  public Result scan(byte[] bytes) {
    return next;
  }
}
