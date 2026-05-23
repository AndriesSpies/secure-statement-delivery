package com.capitec.ssd.adapters.persistence;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface StatementJpaRepository extends JpaRepository<StatementEntity, UUID> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query(
      value =
          """
            SELECT * FROM statement
            WHERE status = 'QUARANTINED'
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT :limit
            """,
      nativeQuery = true)
  List<StatementEntity> claimQuarantined(@Param("limit") int limit);

  List<StatementEntity> findByCustomerIdOrderByCreatedAtDesc(String customerId, Limit limit);
}
