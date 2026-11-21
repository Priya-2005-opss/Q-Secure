
package com.qsecure.qsecure;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/api/dns")
@CrossOrigin(origins = "*")
public class DnsAuthenticationController {

    private final DnsAuthenticationService dnsService;

    public DnsAuthenticationController(
            DnsAuthenticationService dnsService) {
        this.dnsService = dnsService;
    }

    public record DnsRequest(
        String domain,
        String selector
    ) {}

    @PostMapping("/check")
    public Map<String, String> checkAuthentication(
            @RequestBody DnsRequest request) {

        if (request == null ||
            request.domain() == null ||
            request.domain().isBlank()) {

            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Please provide a sender domain."
            );
        }

        return dnsService.checkDomain(
            request.domain(),
            request.selector()
        );
    }
}
