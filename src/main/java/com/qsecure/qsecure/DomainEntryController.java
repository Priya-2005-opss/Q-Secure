
package com.qsecure.qsecure;

import java.util.List;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/domains")
public class DomainEntryController {

    private final DomainEntryRepository repository;

    public DomainEntryController(DomainEntryRepository repository) {
        this.repository = repository;
    }

    private String getCurrentUserEmail() {
        Authentication auth =
            SecurityContextHolder.getContext().getAuthentication();

        if (auth == null ||
        !auth.isAuthenticated() ||
        "anonymousUser".equals(auth.getName())) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Please log in first."
            );
        }

        return auth.getName();
    }

    @GetMapping
    public List<DomainEntry> getDomains() {
        return repository.findByUserEmailOrderByCreatedAtDesc(
            getCurrentUserEmail()
        );
    }

    @PostMapping
    public DomainEntry addDomain(@RequestBody DomainRequest request) {

        String userEmail = getCurrentUserEmail();

        if (request.domain() == null || request.category() == null) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Domain and category are required."
            );
        }

        String domain = request.domain().trim()
            .toLowerCase(Locale.ROOT);

        String category = request.category().trim()
            .toUpperCase(Locale.ROOT);

        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }

        if (!domain.matches(
                "(?=.{1,253}$)[a-z0-9]+([.-][a-z0-9]+)*\\.[a-z]{2,63}")) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Enter a valid domain name."
            );
        }

        if (!category.equals("TRUSTED")
                && !category.equals("SUSPICIOUS")) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Category must be TRUSTED or SUSPICIOUS."
            );
        }

        if (repository.existsByUserEmailAndDomainAndCategory(
                userEmail, domain, category)) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT, "This domain is already in your list."
            );
        }

        DomainEntry entry = new DomainEntry();
        entry.setUserEmail(userEmail);
        entry.setDomain(domain);
        entry.setCategory(category);

        return repository.save(entry);
    }

    @DeleteMapping("/{id}")
    public String deleteDomain(@PathVariable Long id) {

        String userEmail = getCurrentUserEmail();

        DomainEntry entry = repository.findByIdAndUserEmail(id, userEmail)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Domain entry not found."
            ));

        repository.delete(entry);

        return "Domain deleted successfully.";
    }

    public record DomainRequest(String domain, String category) {
    }
}
