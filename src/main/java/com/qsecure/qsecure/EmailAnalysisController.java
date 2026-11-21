
package com.qsecure.qsecure;

import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.regex.*;
import java.net.URI;
import java.net.IDN;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
@RequestMapping("/api/email")
public class EmailAnalysisController {
    private final ThreatHistoryRepository threatHistoryRepository;
private final DomainEntryRepository domainEntryRepository;

public EmailAnalysisController(
        ThreatHistoryRepository threatHistoryRepository,
        DomainEntryRepository domainEntryRepository) {

    this.threatHistoryRepository = threatHistoryRepository;
    this.domainEntryRepository = domainEntryRepository;
}
public record AnalyzeRequest(String emailText, String storageKey) {

    public AnalyzeRequest(String emailText) {
        this(emailText, null);
    }
}

    public record AnalyzeResponse(
        int riskScore,
        String threatLevel,
        List<String> threats,
        List<String> recommendations,
        Map<String, String> authentication,
        String quantumAssessment,
        String quantumDetails,
        List<String> detectedUrls
    ) {}

    private static final Map<String, String> BRANDS = Map.of(
        "paypal", "PayPal",
        "google", "Google",
        "amazon", "Amazon",
        "microsoft", "Microsoft",
        "apple", "Apple"
    );

    @PostMapping("/analyze")
    public AnalyzeResponse analyzeEmail(@RequestBody AnalyzeRequest request) {

        if (request.emailText() == null ||
            request.emailText().isBlank()) {
            throw new IllegalArgumentException(
                "Please enter an email to analyze."
            );
        }

        String originalEmail = request.emailText();
        String email = originalEmail.toLowerCase(Locale.ROOT);

        int score = 0;

        List<String> threats = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        List<String> urls = new ArrayList<>();
        // Load domain lists belonging to the logged-in user
Authentication scanAuth =
    SecurityContextHolder.getContext().getAuthentication();

if (scanAuth == null ||
    !scanAuth.isAuthenticated() ||
    "anonymousUser".equals(scanAuth.getName())) {

    throw new IllegalStateException("Please log in first.");
}

String scanUserEmail = scanAuth.getName();

List<DomainEntry> suspiciousDomains =
    domainEntryRepository
        .findByUserEmailAndCategoryOrderByCreatedAtDesc(
            scanUserEmail, "SUSPICIOUS"
        );

List<DomainEntry> trustedDomains =
    domainEntryRepository
        .findByUserEmailAndCategoryOrderByCreatedAtDesc(
            scanUserEmail, "TRUSTED"
        );

       // 1. Advanced phishing keyword detection

// Urgency and pressure tactics
String[] urgencyWords = {
    "urgent", "immediately", "act now", "final warning",
    "within 24 hours", "limited time", "expires today"
};

boolean urgencyDetected = false;
for (String word : urgencyWords) {
    if (email.contains(word)) {
        urgencyDetected = true;
        break;
    }
}
if (urgencyDetected) {
    score += 10;
    threats.add("Urgency or pressure tactics detected.");
}

// Account threats
String[] accountThreatWords = {
    "account suspended", "account blocked", "account locked",
    "account compromised", "unauthorized access",
    "account will be closed"
};

boolean accountThreatDetected = false;
for (String word : accountThreatWords) {
    if (email.contains(word)) {
        accountThreatDetected = true;
        break;
    }
}
if (accountThreatDetected) {
    score += 15;
    threats.add("Possible account threat or suspension detected.");
}

// Credential and financial information requests
String[] credentialWords = {
    "enter your password", "confirm your password",
    "login credentials", "bank details", "card number",
    "cvv", "atm pin", "credit card details"
};

boolean credentialDetected = false;
for (String word : credentialWords) {
    if (email.contains(word)) {
        credentialDetected = true;
        break;
    }
}
if (credentialDetected) {
    score += 20;
    threats.add("Sensitive credential or financial information request detected.");
}

// OTP and verification code requests
String[] otpWords = {
    "otp", "one-time password", "verification code",
    "security code", "share the code"
};

boolean otpDetected = false;
for (String word : otpWords) {
    if (email.contains(word)) {
        otpDetected = true;
        break;
    }
}
if (otpDetected) {
    score += 20;
    threats.add("Possible OTP or verification code theft detected.");
}

// Secrecy and support avoidance
String[] secrecyWords = {
    "do not contact support", "do not tell anyone",
    "keep this confidential", "do not share this information"
};

boolean secrecyDetected = false;
for (String word : secrecyWords) {
    if (email.contains(word)) {
        secrecyDetected = true;
        break;
    }
}
if (secrecyDetected) {
    score += 10;
    threats.add("Suspicious secrecy or support-avoidance instruction detected.");
}

// Brand or security-team impersonation language
String[] impersonationWords = {
    "bank security team", "security department",
    "fraud prevention team", "account protection team"
};

boolean impersonationDetected = false;
for (String word : impersonationWords) {
    if (email.contains(word)) {
        impersonationDetected = true;
        break;
    }
}
if (impersonationDetected) {
    score += 10;
    threats.add("Possible organization or security-team impersonation detected.");
}

        // 2. Extract URLs
        Pattern urlPattern = Pattern.compile(
            "(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+"
        );

        Matcher matcher = urlPattern.matcher(originalEmail);

        while (matcher.find()) {

            String url = matcher.group();

            // Remove common punctuation at the end of a URL
            url = url.replaceAll("[.,;!?)]*$", "");

            urls.add(url);

            String lowerUrl = url.toLowerCase(Locale.ROOT);

            if (lowerUrl.startsWith("http://")) {
                score += 10;
                threats.add("Unencrypted HTTP link detected: " + url);
            }

            // 3. URL shortener detection
            String[] shorteners = {
                "bit.ly", "tinyurl.com", "t.co",
                "goo.gl", "is.gd", "ow.ly", "cutt.ly"
            };

            for (String shortener : shorteners) {
                if (lowerUrl.contains(shortener)) {
                    score += 15;
                    threats.add("Shortened URL detected: " + url);
                    break;
                }
            }

            // 4. Advanced domain analysis
            String host = extractHost(url);

            if (host != null && !host.isBlank()) {

                String domain = host.toLowerCase(Locale.ROOT);
                // Check whether the URL belongs to a user-listed suspicious domain
// Convert internationalized domain to ASCII
try {
    domain = IDN.toASCII(domain);
} catch (IllegalArgumentException ignored) {
    score += 15;
    threats.add(
        "Invalid or suspicious international domain detected: " + host
    );
}

// Create a final copy for lambda expressions
final String domainToCheck = domain;

// Check suspicious domains
boolean suspiciousMatch = suspiciousDomains.stream().anyMatch(entry ->
    domainToCheck.equals(entry.getDomain()) ||
    domainToCheck.endsWith("." + entry.getDomain())
);

if (suspiciousMatch) {
    String warning = "User-listed suspicious domain detected: " + domainToCheck;

    if (!threats.contains(warning)) {
        score += 25;
        threats.add(warning);
        recommendations.add(
            "Avoid interacting with this domain because it is on your suspicious domain list."
        );
    }
}

// Recognize trusted domains without reducing the risk score
boolean trustedMatch = trustedDomains.stream().anyMatch(entry ->
    domainToCheck.equals(entry.getDomain()) ||
    domainToCheck.endsWith("." + entry.getDomain())
);

if (trustedMatch) {
    recommendations.add(
        "Recognized domain from your trusted list: " + domainToCheck +
        ". This does not guarantee that the email is safe."
    );
}
                // IP address URL detection
                if (isIpAddress(domain)) {
                    score += 20;
                    threats.add(
                        "URL uses an IP address instead of a domain: " + url
                    );
                }

                // Punycode detection
                if (domain.contains("xn--")) {
                    score += 20;
                    threats.add(
                        "Punycode domain detected; possible homograph risk: " + domain
                    );
                }

                // Suspicious subdomain detection
                String[] labels = domain.split("\\.");

                if (labels.length >= 5) {
                    score += 15;
                    threats.add(
                        "Excessive subdomains detected: " + domain
                    );
                }

                // Detect brand impersonation and lookalike domains
                String mainDomain = getMainDomain(domain);

                for (Map.Entry<String, String> brand : BRANDS.entrySet()) {

                    String officialName = brand.getKey();
                    String brandName = brand.getValue();

                    if (mainDomain.contains(officialName) &&
                        !mainDomain.equals(officialName)) {

                        score += 20;
                        threats.add(
                            "Possible " + brandName +
                            " brand impersonation detected: " + domain
                        );
                        break;
                    }

                    if (!mainDomain.equals(officialName) &&
                        levenshtein(mainDomain, officialName) <= 1) {

                        score += 25;
                        threats.add(
                            "Lookalike domain resembling " +
                            brandName + " detected: " + domain
                        );
                        break;
                    }
                }

                // Suspicious domain structure
                for (String label : labels) {

                    if (label.length() > 25) {
                        score += 10;
                        threats.add(
                            "Unusually long domain label detected: " + domain
                        );
                        break;
                    }

                    if (label.matches(".*[0-9].*[a-z].*") &&
                        label.matches(".*[a-z].*[0-9].*")) {

                        score += 10;
                        threats.add(
                            "Mixed letters and numbers in domain: " + domain
                        );
                        break;
                    }
                }

                // Suspicious hyphen usage
                if (domain.contains("--") && !domain.contains("xn--")) {
                    score += 10;
                    threats.add(
                        "Suspicious consecutive hyphens in domain: " + domain
                    );
                }
            }
        }


        // 5. Advanced sender identity and spoofing detection

        String fromHeader = getHeaderValue(originalEmail, "From");
        String replyToHeader = getHeaderValue(originalEmail, "Reply-To");

        String senderAddress = extractEmailAddress(fromHeader);
        String replyToAddress = extractEmailAddress(replyToHeader);

        if (senderAddress != null) {

            String senderDomain = getEmailDomain(senderAddress);
            String senderMainDomain = getMainDomain(senderDomain);

            // Detect display-name brand impersonation
            String displayName = fromHeader
                    .replace(senderAddress, "")
                    .replaceAll("[\"<>]", "")
                    .trim()
                    .toLowerCase(Locale.ROOT);

            for (Map.Entry<String, String> brand : BRANDS.entrySet()) {

                String brandKey = brand.getKey();

                if (displayName.contains(brandKey)
                        && !senderMainDomain.equals(brandKey)) {

                    score += 25;

                    threats.add(
                        "Possible sender display-name spoofing: " +
                        brand.getValue() +
                        " name used with unrelated sender domain: " +
                        senderDomain
                    );

                    recommendations.add(
                        "Verify the sender's actual email address before trusting the message."
                    );

                    break;
                }
            }

            // Detect Reply-To domain mismatch
            if (replyToAddress != null) {

                String replyDomain = getEmailDomain(replyToAddress);

                if (replyDomain != null &&
                        !senderDomain.equalsIgnoreCase(replyDomain)) {

                    score += 20;

                    threats.add(
                        "Sender and Reply-To domains do not match: " +
                        senderDomain + " / " + replyDomain
                    );

                    recommendations.add(
                        "Do not reply until the Reply-To address has been independently verified."
                    );
                }
            }

            // Detect suspicious sender domain patterns
            if (senderDomain != null &&
                    (senderDomain.contains("xn--") ||
                     senderDomain.contains("--"))) {

                score += 15;

                threats.add(
                    "Suspicious sender domain structure detected: " +
                    senderDomain
                );

                recommendations.add(
                    "Verify the sender domain carefully before sharing sensitive information."
                );
            }
        }

        // 5. Authentication header analysis
        Map<String, String> authentication = new LinkedHashMap<>();

        authentication.put("SPF", checkAuthentication(email, "spf"));
        authentication.put("DKIM", checkAuthentication(email, "dkim"));
        authentication.put("DMARC", checkAuthentication(email, "dmarc"));

        for (Map.Entry<String, String> entry : authentication.entrySet()) {
            if ("FAIL".equals(entry.getValue())) {
                score += 15;
                threats.add(
                    entry.getKey() + " authentication failure reported."
                );
            }
        }

        // 6. Quantum risk simulation
        boolean legacyCrypto =
            email.contains("rsa") ||
            email.contains("sha1") ||
            email.contains("ecdsa") ||
            email.contains("diffie-hellman");

        String quantumAssessment;
        String quantumDetails;

        if (legacyCrypto) {

            quantumAssessment =
                "Potential legacy cryptography exposure";

            quantumDetails =
                "Legacy cryptographic algorithm indicators were found. " +
                "This is a simulated post-quantum readiness warning, " +
                "not evidence of an actual quantum attack.";

        } else {

            quantumAssessment =
                "No legacy algorithm indicators found";

            quantumDetails =
                "No recognized legacy cryptographic indicators were found " +
                "in the supplied text. Actual cryptographic strength " +
                "cannot be established from email text alone.";
        }

        // 7. Final risk calculation
        score = Math.min(score, 100);

        String threatLevel;

        if (score >= 76) {
            threatLevel = "CRITICAL";
        } else if (score >= 51) {
            threatLevel = "HIGH";
        } else if (score >= 26) {
            threatLevel = "MEDIUM";
        } else {
            threatLevel = "LOW";
        }

        if (threats.isEmpty()) {
            threats.add(
                "No suspicious patterns detected by the current rules."
            );
        }

        recommendations.add(
            "Do not open unexpected links or attachments."
        );

        recommendations.add(
            "Verify sensitive requests through an independent trusted channel."
        );

        recommendations.add(
            "Treat missing authentication results as unverified, not as passed."
        );

        recommendations.add(
            "Check suspicious domains carefully before entering personal information."
        );

        AnalyzeResponse response = new AnalyzeResponse(
    score,
    threatLevel,
    threats,
    recommendations,
    authentication,
    quantumAssessment,
    quantumDetails,
    urls
);



// Create database record
ThreatHistory history = new ThreatHistory();

history.setUserEmail(scanUserEmail);
history.setEmailContent(originalEmail);
history.setStorageKey(request.storageKey());
history.setRiskScore(score);
history.setThreatLevel(threatLevel);
history.setThreats(String.join("\n", threats));
history.setRecommendations(String.join("\n", recommendations));
history.setAuthentication(authentication.toString());
history.setDetectedUrls(String.join("\n", urls));
history.setQuantumAssessment(quantumAssessment);
history.setQuantumDetails(quantumDetails);

threatHistoryRepository.save(history);

return response;
    }


    // Extract a specific email header
    private String getHeaderValue(String emailText, String headerName) {

        Pattern pattern = Pattern.compile(
            "(?im)^" + Pattern.quote(headerName) + "\\s*:\\s*(.+)$"
        );

        Matcher matcher = pattern.matcher(emailText);

        if (matcher.find()) {
            return matcher.group(1).trim();
        }

        return null;
    }

    // Extract email address from a header value
    private String extractEmailAddress(String headerValue) {

        if (headerValue == null) {
            return null;
        }

        Pattern pattern = Pattern.compile(
            "[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
            Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = pattern.matcher(headerValue);

        if (matcher.find()) {
            return matcher.group().toLowerCase(Locale.ROOT);
        }

        return null;
    }

    // Extract domain from an email address
    private String getEmailDomain(String emailAddress) {

        if (emailAddress == null) {
            return null;
        }

        int atIndex = emailAddress.lastIndexOf("@");

        if (atIndex < 0 || atIndex == emailAddress.length() - 1) {
            return null;
        }

        return emailAddress.substring(atIndex + 1)
                .toLowerCase(Locale.ROOT);
    }

    // Extract hostname from a URL
    private String extractHost(String url) {

        try {
            String formattedUrl = url;

            if (formattedUrl.toLowerCase(Locale.ROOT).startsWith("www.")) {
                formattedUrl = "https://" + formattedUrl;
            }

            URI uri = URI.create(formattedUrl);

            return uri.getHost();

        } catch (Exception e) {
            return null;
        }
    }

    // Identify IPv4 address URLs
    private boolean isIpAddress(String host) {

        return host.matches(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
        );
    }

    // Obtain the main domain label for comparison.
    // This is a simplified heuristic, not a public-suffix database.
    private String getMainDomain(String domain) {

        String[] labels = domain.split("\\.");

        if (labels.length < 2) {
            return domain;
        }

        return labels[labels.length - 2];
    }

    // Calculate edit distance for lookalike-domain comparison
    private int levenshtein(String first, String second) {

        int[][] dp = new int[first.length() + 1][second.length() + 1];

        for (int i = 0; i <= first.length(); i++) {
            dp[i][0] = i;
        }

        for (int j = 0; j <= second.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= first.length(); i++) {

            for (int j = 1; j <= second.length(); j++) {

                int cost = first.charAt(i - 1) ==
                           second.charAt(j - 1) ? 0 : 1;

                dp[i][j] = Math.min(
                    Math.min(
                        dp[i - 1][j] + 1,
                        dp[i][j - 1] + 1
                    ),
                    dp[i - 1][j - 1] + cost
                );
            }
        }

        return dp[first.length()][second.length()];
    }

    private String checkAuthentication(String email, String protocol) {

        Pattern pattern = Pattern.compile(
            "(?i)" + protocol +
            "\\s*=\\s*(pass|fail|softfail|neutral|none)"
        );

        Matcher matcher = pattern.matcher(email);

        if (!matcher.find()) {
            return "NOT PROVIDED";
        }

        String result = matcher.group(1).toUpperCase(Locale.ROOT);

        if ("SOFTFAIL".equals(result)) {
            return "SOFTFAIL";
        }

        return result;
    }
}
