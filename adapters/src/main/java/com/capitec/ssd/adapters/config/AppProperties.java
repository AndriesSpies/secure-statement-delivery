package com.capitec.ssd.adapters.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("ssd")
public record AppProperties(
    Upload upload, Link link, Storage storage, Crypto crypto, Scanner scanner, Security security) {
  public record Upload(long maxBytes) {}

  public record Link(long defaultTtlSeconds, int defaultMaxDownloads) {}

  public record Storage(
      String bucket,
      String endpoint,
      String region,
      String accessKey,
      String secretKey,
      boolean pathStyle) {}

  public record Crypto(String kekFilePath, String kekKeyId) {}

  public record Scanner(String host, int port, long failureThreshold) {}

  public record Security(String devTokenSecret) {}
}
