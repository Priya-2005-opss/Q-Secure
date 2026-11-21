
package com.qsecure.qsecure;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.util.Map;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/qr")
@CrossOrigin(origins = "*")
public class QRAnalysisController {

    private final EmailAnalysisController emailController;

    public QRAnalysisController(EmailAnalysisController emailController) {
        this.emailController = emailController;
    }

    @PostMapping(
        value = "/analyze",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public Map<String, Object> analyzeQR(
        @RequestParam("file") MultipartFile file
    ) throws Exception {

        if (file.isEmpty()) {
            throw new IllegalArgumentException(
                "Please upload a QR image."
            );
        }

        BufferedImage image = ImageIO.read(file.getInputStream());

        if (image == null) {
            throw new IllegalArgumentException(
                "Invalid image. Upload a PNG or JPG image."
            );
        }

        LuminanceSource source =
            new BufferedImageLuminanceSource(image);

        BinaryBitmap bitmap =
            new BinaryBitmap(new HybridBinarizer(source));

        Result result = new MultiFormatReader().decode(bitmap);

        String decodedText = result.getText().trim();

        // Normalize URL-like QR content before analysis
        String analysisText = normalizeQRContent(decodedText);

        EmailAnalysisController.AnalyzeResponse analysis =
            emailController.analyzeEmail(
                new EmailAnalysisController.AnalyzeRequest(analysisText)
            );

        return Map.of(
            "decodedText", decodedText,
            "analysis", analysis
        );
    }

    private String normalizeQRContent(String content) {

        if (content == null || content.isBlank()) {
            return content;
        }

        String value = content.trim();

        // Already has a URL scheme
        if (value.matches("(?i)^[a-z][a-z0-9+.-]*:.*")) {
            return value;
        }

        // Convert www.example.com into an HTTPS URL
        if (value.matches("(?i)^www\\..+")) {
            return "https://" + value;
        }

        // Convert bare domains and domain/path QR links
        Pattern domainPattern = Pattern.compile(
            "(?i)^[a-z0-9-]+(\\.[a-z0-9-]+)+(:\\d+)?(/[^\\s]*)?$"
        );

        if (domainPattern.matcher(value).matches()) {
            return "https://" + value;
        }

        // Leave ordinary text, email addresses and other QR content unchanged
        return value;
    }
}
