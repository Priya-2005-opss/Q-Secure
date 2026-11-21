
package com.qsecure.qsecure;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ThreatHistoryRepository
        extends JpaRepository<ThreatHistory, Long> {

    List<ThreatHistory> findByUserEmailOrderByCreatedAtDesc(
            String userEmail
    );

    long countByUserEmail(String userEmail);
}
