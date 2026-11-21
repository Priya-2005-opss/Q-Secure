
package com.qsecure.qsecure;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

@Service
public class StorageQuotaService {

    @Value("${qsecure.storage.location:./qsecure-storage}")
    private String storageLocation;

    @Value("${qsecure.storage.max-size-bytes:42949672960}")
    private long maxSizeBytes;

    @Value("${qsecure.storage.warning-percent:80}")
    private int warningPercent;

    public Path getStorageDirectory() throws IOException {
        Path directory = Paths.get(storageLocation)
                .toAbsolutePath()
                .normalize();

        Files.createDirectories(directory);
        return directory;
    }

    public long getUsedBytes() throws IOException {
        Path directory = getStorageDirectory();
        long totalBytes = 0;

        try (Stream<Path> files = Files.walk(directory)) {
            for (Path path : files.filter(Files::isRegularFile).toList()) {
                totalBytes = Math.addExact(totalBytes, Files.size(path));
            }
        }

        return totalBytes;
    }

    public synchronized void checkAvailableSpace(long incomingBytes)
            throws IOException {

        if (incomingBytes < 0 || incomingBytes > maxSizeBytes) {
            throw new ResponseStatusException(
                    HttpStatus.PAYLOAD_TOO_LARGE,
                    "File exceeds Q-Secure storage capacity."
            );
        }

        long usedBytes = getUsedBytes();

        if (usedBytes > maxSizeBytes ||
                incomingBytes > maxSizeBytes - usedBytes) {
            throw new ResponseStatusException(
                    HttpStatus.INSUFFICIENT_STORAGE,
                    "Q-Secure storage limit of 40 GB has been reached."
            );
        }

        long projectedUsage = usedBytes + incomingBytes;
        int usagePercent =
                (int) ((projectedUsage * 100.0) / maxSizeBytes);

        if (usagePercent >= warningPercent) {
            System.out.println(
                    "WARNING: Q-Secure storage usage is "
                    + usagePercent + "%."
            );
        }
    }
}
