
package com.qsecure.qsecure;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository userRepository;
    private final ThreatHistoryRepository historyRepository;

    public AdminController(
            UserRepository userRepository,
            ThreatHistoryRepository historyRepository) {

        this.userRepository = userRepository;
        this.historyRepository = historyRepository;
    }

    public record AdminUserResponse(
            Long id,
            String fullName,
            String email,
            String role,
            long totalScans
    ) {}

    @GetMapping("/users")
    public ResponseEntity<?> getUsers(Authentication authentication) {

        if (authentication == null ||
                !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getName())) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Please log in."));
        }

        boolean isAdmin = authentication.getAuthorities()
                .stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("ROLE_ADMIN"));

        if (!isAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message",
                            "Administrator access required."));
        }

        List<AdminUserResponse> users =
                userRepository.findAll()
                        .stream()
                        .map(user -> new AdminUserResponse(
                                user.getId(),
                                user.getFullName(),
                                user.getEmail(),
                                user.getRole(),
                                historyRepository.countByUserEmail(
                                        user.getEmail()
                                )
                        ))
                        .toList();

        return ResponseEntity.ok(users);
    }

    @GetMapping("/summary")
    public ResponseEntity<?> getSummary(Authentication authentication) {

        if (authentication == null ||
                !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getName())) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Please log in."));
        }

        boolean isAdmin = authentication.getAuthorities()
                .stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("ROLE_ADMIN"));

        if (!isAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message",
                            "Administrator access required."));
        }

        long totalUsers = userRepository.count();
        long totalScans = historyRepository.count();

        return ResponseEntity.ok(Map.of(
                "totalUsers", totalUsers,
                "totalScans", totalScans
        ));
    }

    
@PutMapping("/users/{id}/role")
public ResponseEntity<?> updateUserRole(
        @PathVariable Long id,
        @RequestBody Map<String, String> request,
        Authentication authentication) {

    if (authentication == null ||
            !authentication.isAuthenticated() ||
            "anonymousUser".equals(authentication.getName())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Please log in."));
    }

    boolean isAdmin = authentication.getAuthorities()
            .stream()
            .anyMatch(authority ->
                    authority.getAuthority().equals("ROLE_ADMIN"));

    if (!isAdmin) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("message", "Administrator access required."));
    }

    String newRole = request.get("role");

    if (newRole == null ||
            (!newRole.equals("USER") && !newRole.equals("ADMIN"))) {
        return ResponseEntity.badRequest()
                .body(Map.of("message", "Role must be USER or ADMIN."));
    }

    var optionalUser = userRepository.findById(id);

    if (optionalUser.isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("message", "User not found."));
    }

    User user = optionalUser.get();

    if (user.getEmail().equalsIgnoreCase(authentication.getName())
            && newRole.equals("USER")) {
        return ResponseEntity.badRequest()
                .body(Map.of("message",
                        "You cannot remove your own admin role."));
    }

    user.setRole(newRole);
    userRepository.save(user);

    return ResponseEntity.ok(
            Map.of(
                    "message", "User role updated successfully.",
                    "email", user.getEmail(),
                    "role", user.getRole()
            )
    );
}
}
  