
package com.qsecure.qsecure;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface DomainEntryRepository
        extends JpaRepository<DomainEntry, Long> {

    List<DomainEntry> findByUserEmailOrderByCreatedAtDesc(
        String userEmail
    );

    List<DomainEntry> findByUserEmailAndCategoryOrderByCreatedAtDesc(
        String userEmail,
        String category
    );

    Optional<DomainEntry> findByIdAndUserEmail(
        Long id,
        String userEmail
    );

    boolean existsByUserEmailAndDomainAndCategory(
        String userEmail,
        String domain,
        String category
    );
}
