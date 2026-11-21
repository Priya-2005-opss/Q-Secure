
package com.qsecure.qsecure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/storage")
public class StorageController {

    private final StorageQuotaService storageQuotaService;

    public StorageController(StorageQuotaService storageQuotaService) {
        this.storageQuotaService = storageQuotaService;
    }

    @GetMapping("/usage")
    public Map<String, Object> getStorageUsage() throws IOException {

        long usedBytes = storageQuotaService.getUsedBytes();
        long maxBytes = 42949672960L;

        double usedGB = usedBytes / (1024.0 * 1024 * 1024);
        double maxGB = maxBytes / (1024.0 * 1024 * 1024);
        double percentage = (usedBytes * 100.0) / maxBytes;

        return Map.of(
            "usedBytes", usedBytes,
            "usedGB", Math.round(usedGB * 100.0) / 100.0,
            "maxGB", maxGB,
            "availableGB", Math.round((maxGB - usedGB) * 100.0) / 100.0,
            "usagePercentage", Math.round(percentage * 100.0) / 100.0,
            "warning", percentage >= 80
        );
    }
}
