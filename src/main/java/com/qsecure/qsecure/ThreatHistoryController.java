
package com.qsecure.qsecure;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.List;

@RestController
@RequestMapping("/api/history")
public class ThreatHistoryController {

    private final ThreatHistoryRepository repository;

    public ThreatHistoryController(ThreatHistoryRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public ResponseEntity<List<ThreatHistory>> getHistory(
            Authentication authentication) {

       if (authentication == null ||
    !authentication.isAuthenticated() ||
    "anonymousUser".equals(authentication.getName())) {

    return ResponseEntity.status(401).build();
}

        List<ThreatHistory> history =
            repository.findByUserEmailOrderByCreatedAtDesc(
                authentication.getName()
            );

        return ResponseEntity.ok(history);
    }
}
