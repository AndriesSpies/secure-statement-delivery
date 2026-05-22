package com.capitec.ssd.application.fakes;

import com.capitec.ssd.application.port.out.PdfValidator;

public class ScriptedPdfValidator implements PdfValidator {
  public Result next = new Result.Valid();

  @Override
  public Result validate(byte[] bytes) {
    return next;
  }
}
