
package com.qsecure.qsecure;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_history")
public class ThreatHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_email", nullable = false)
    private String userEmail;

    @Column(name = "email_content", columnDefinition = "TEXT")
    private String emailContent;
    @Column(name = "storage_key")
private String storageKey;

    private Integer riskScore;

    private String threatLevel;

    @Column(columnDefinition = "TEXT")
    private String threats;

    @Column(columnDefinition = "TEXT")
    private String recommendations;

    @Column(columnDefinition = "TEXT")
    private String authentication;

    @Column(columnDefinition = "TEXT")
    private String quantumAssessment;

    @Column(columnDefinition = "TEXT")
    private String quantumDetails;

    @Column(columnDefinition = "TEXT")
    private String detectedUrls;

    private LocalDateTime createdAt;

    @PrePersist
    public void beforeSave() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    public Long getId() { return id; }

    public String getUserEmail() { return userEmail; }
    public void setUserEmail(String userEmail) { this.userEmail = userEmail; }

    public String getEmailContent() { return emailContent; }
    public void setEmailContent(String emailContent) { this.emailContent = emailContent; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public String getThreatLevel() { return threatLevel; }
    public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }

    public String getThreats() { return threats; }
    public void setThreats(String threats) { this.threats = threats; }

    public String getRecommendations() { return recommendations; }
    public void setRecommendations(String recommendations) { this.recommendations = recommendations; }

    public String getAuthentication() { return authentication; }
    public void setAuthentication(String authentication) { this.authentication = authentication; }

    public String getQuantumAssessment() { return quantumAssessment; }
    public void setQuantumAssessment(String quantumAssessment) { this.quantumAssessment = quantumAssessment; }

    public String getQuantumDetails() { return quantumDetails; }
    public void setQuantumDetails(String quantumDetails) { this.quantumDetails = quantumDetails; }

    public String getDetectedUrls() { return detectedUrls; }
    public void setDetectedUrls(String detectedUrls) { this.detectedUrls = detectedUrls; }

       public LocalDateTime getCreatedAt() { return createdAt; }

    public String getStorageKey() {
        return storageKey;
    }

    public void setStorageKey(String storageKey) {
        this.storageKey = storageKey;
    }
}