package com.capitec.ssd.adapters.persistence;

import com.capitec.ssd.application.port.out.StatementRepository;
import com.capitec.ssd.domain.common.ByteSize;
import com.capitec.ssd.domain.common.CustomerId;
import com.capitec.ssd.domain.common.MediaType;
import com.capitec.ssd.domain.common.Sha256;
import com.capitec.ssd.domain.common.StatementId;
import com.capitec.ssd.domain.statement.Statement;
import com.capitec.ssd.domain.statement.StatementStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class JpaStatementRepository implements StatementRepository {

  private final StatementJpaRepository jpa;

  public JpaStatementRepository(StatementJpaRepository jpa) {
    this.jpa = jpa;
  }

  @Override
  public void save(Statement s) {
    jpa.save(toEntity(s));
  }

  @Override
  @Transactional(readOnly = true)
  public Optional<Statement> findById(StatementId id) {
    return jpa.findById(id.value()).map(JpaStatementRepository::toDomain);
  }

  @Override
  public List<Statement> findQuarantinedBatch(int limit) {
    return jpa.claimQuarantined(limit).stream().map(JpaStatementRepository::toDomain).toList();
  }

  @Override
  @Transactional(readOnly = true)
  public List<Statement> findByCustomer(CustomerId customer, int limit, int offset) {
    return jpa
        .findByCustomerIdOrderByCreatedAtDesc(customer.value(), Limit.of(limit + offset))
        .stream()
        .skip(offset)
        .limit(limit)
        .map(JpaStatementRepository::toDomain)
        .toList();
  }

  static StatementEntity toEntity(Statement s) {
    var e = new StatementEntity();
    e.setId(s.id().value());
    e.setCustomerId(s.customerId().value());
    e.setFilename(s.filename());
    e.setSizeBytes(s.size().bytes());
    e.setMediaType(s.mediaType().value());
    e.setSha256(s.sha256().bytes());
    e.setStatus(s.status().name());
    e.setRejectionReason(s.rejectionReason());
    e.setStorageKey(s.storageKey());
    e.setEncryptedDek(s.encryptedDek());
    e.setDekKeyId(s.dekKeyId());
    e.setCreatedAt(s.createdAt());
    e.setCreatedBy(s.createdBy());
    e.setUpdatedAt(s.updatedAt());
    return e;
  }

  static Statement toDomain(StatementEntity e) {
    return Statement.rehydrate(
        StatementId.of(e.getId()),
        new CustomerId(e.getCustomerId()),
        e.getFilename(),
        new ByteSize(e.getSizeBytes()),
        new Sha256(e.getSha256()),
        MediaType.of(e.getMediaType()),
        e.getStorageKey(),
        e.getEncryptedDek(),
        e.getDekKeyId(),
        e.getCreatedBy(),
        e.getCreatedAt(),
        StatementStatus.valueOf(e.getStatus()),
        e.getRejectionReason(),
        e.getUpdatedAt());
  }
}
