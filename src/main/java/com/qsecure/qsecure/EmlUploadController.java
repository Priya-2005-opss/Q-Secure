
package com.qsecure.qsecure;

import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Locale;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;
@RestController
@RequestMapping("/api/email")
public class EmlUploadController {
    private static final long MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
private static final int MAX_BULK_FILES = 10;

    private final EmailAnalysisController emailController;
private final StorageQuotaService storageQuotaService;

public EmlUploadController(
        EmailAnalysisController emailController,
        StorageQuotaService storageQuotaService) {
    this.emailController = emailController;
    this.storageQuotaService = storageQuotaService;
}

    @PostMapping(
        value = "/upload-eml",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    
public EmlResponse uploadEml(
        @RequestParam("file") MultipartFile file) {

    if (file.isEmpty()) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Please select an EML file."
        );
    }

    if (file.getSize() > MAX_FILE_SIZE_BYTES) {
        throw new ResponseStatusException(
            HttpStatus.PAYLOAD_TOO_LARGE,
            "EML file size must not exceed 10 MB."
        );
    }

    String filename = file.getOriginalFilename();

    if (filename == null ||
        !filename.toLowerCase(Locale.ROOT).endsWith(".eml")) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Only .eml files are supported."
        );
    }

    Path savedFile = null;

    try {
        // Check storage capacity
        storageQuotaService.checkAvailableSpace(file.getSize());

        // Save original EML file
        Path storageDirectory =
            storageQuotaService.getStorageDirectory();

        String storedFilename = UUID.randomUUID() + ".eml";
        savedFile = storageDirectory.resolve(storedFilename);

        try (InputStream fileInput = file.getInputStream()) {
            Files.copy(
                fileInput,
                savedFile,
                StandardCopyOption.REPLACE_EXISTING
            );
        }

        // Parse the saved EML file
        try (InputStream input = Files.newInputStream(savedFile)) {

            Session session = Session.getDefaultInstance(
                new Properties()
            );

            MimeMessage message = new MimeMessage(session, input);

            String sender = "";
            if (message.getFrom() != null &&
                message.getFrom().length > 0) {
                sender = message.getFrom()[0].toString();
            }

            String subject = message.getSubject() == null
                ? "" : MimeUtility.decodeText(message.getSubject());

            String body = extractBody(message);

            Map<String, String> headers = new LinkedHashMap<>();

            addHeader(message, headers, "Authentication-Results");
            addHeader(message, headers, "Received-SPF");
            addHeader(message, headers, "DKIM-Signature");

            String dkimHeader = headers.getOrDefault(
                "DKIM-Signature", ""
            );

            String selector = extractDkimSelector(dkimHeader);

            String emailText =
                "From: " + sender +
                "\nSubject: " + subject +
                "\n" + headers.toString() +
                "\n" + body;

            EmailAnalysisController.AnalyzeResponse analysis =
                emailController.analyzeEmail(
                    new EmailAnalysisController.AnalyzeRequest(
                        emailText, storedFilename
                    )
                );

            return new EmlResponse(
                filename,
                sender,
                subject,
                selector,
                body,
                headers,
                analysis
            );
        }

    } catch (ResponseStatusException e) {
        deleteSavedFile(savedFile);
        throw e;

    } catch (Exception e) {
        deleteSavedFile(savedFile);
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST,
            "Unable to process EML file: " + e.getMessage()
        );
    }
}

private void deleteSavedFile(Path savedFile) {
    if (savedFile != null) {
        try {
            Files.deleteIfExists(savedFile);
        } catch (java.io.IOException ignored) {
            // Keep the original error.
        }
    }
}

@PostMapping(
    value = "/upload-eml/bulk",
    consumes = MediaType.MULTIPART_FORM_DATA_VALUE
)
public BulkEmlResponse uploadBulkEml(
        @RequestParam("files") List<MultipartFile> files) {

    if (files == null || files.isEmpty()) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST,
            "Please select at least one EML file."
        );
    }
if (files.size() > MAX_BULK_FILES) {
    throw new ResponseStatusException(
        HttpStatus.BAD_REQUEST,
        "You can upload a maximum of 10 EML files at a time."
    );
}
    List<BulkEmlResult> results = new ArrayList<>();

    for (MultipartFile file : files) {
        String filename = file.getOriginalFilename();

        try {
            EmlResponse response = uploadEml(file);

            results.add(new BulkEmlResult(
                filename,
                "SUCCESS",
                "Email analyzed successfully.",
                response
            ));

        } catch (Exception e) {
            results.add(new BulkEmlResult(
                filename,
                "FAILED",
                e.getMessage(),
                null
            ));
        }
    }

    int successful = (int) results.stream()
        .filter(r -> "SUCCESS".equals(r.status()))
        .count();

    int failed = results.size() - successful;

    return new BulkEmlResponse(
        results.size(),
        successful,
        failed,
        results
    );
}

public record BulkEmlResult(
    String filename,
    String status,
    String message,
    EmlResponse result
) {}

public record BulkEmlResponse(
    int totalFiles,
    int successfulScans,
    int failedScans,
    List<BulkEmlResult> results
) {}

    private void addHeader(
            MimeMessage message,
            Map<String, String> headers,
            String name) throws Exception {

        String[] values = message.getHeader(name);

        if (values != null && values.length > 0) {
            headers.put(name, String.join("; ", values));
        }
    }

    private String extractDkimSelector(String header) {

        if (header == null || header.isBlank()) {
            return "";
        }

        Matcher matcher = Pattern.compile(
            "(?:^|;)\\s*s\\s*=\\s*([^;\\s]+)",
            Pattern.CASE_INSENSITIVE
        ).matcher(header);

        return matcher.find() ? matcher.group(1) : "";
    }

    private String extractBody(
            jakarta.mail.Part part) throws Exception {

        Object content = part.getContent();

        if (content instanceof String text) {
            if (part.isMimeType("text/plain")) {
                return text;
            }

            if (part.isMimeType("text/html")) {
                return text.replaceAll(
                    "(?is)<(script|style).*?>.*?</\\1>", " "
                ).replaceAll("(?s)<[^>]*>", " ")
                 .replace("&nbsp;", " ")
                 .replace("&amp;", "&")
                 .replaceAll("\\s+", " ")
                 .trim();
            }
        }

        if (content instanceof Multipart multipart) {
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart bodyPart = multipart.getBodyPart(i);

                if (bodyPart.isMimeType("text/plain")) {
                    return extractBody(bodyPart);
                }

                String extracted = extractBody(bodyPart);

                if (!extracted.isBlank()) {
                    result.append(extracted).append("\n");
                }
            }

            return result.toString();
        }

        return "";
    }

    public record EmlResponse(
        String filename,
        String sender,
        String subject,
        String dkimSelector,
        String emailBody,
        Map<String, String> headers,
        EmailAnalysisController.AnalyzeResponse analysis
    ) {}
}
