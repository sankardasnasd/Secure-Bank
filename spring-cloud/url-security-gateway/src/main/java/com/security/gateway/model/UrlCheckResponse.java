package com.security.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UrlCheckResponse {

    private String targetUrl;
    private Boolean isSecure;
    private String status; // SAFE, SUSPICIOUS, DANGEROUS
    private Integer threatScore; // 0 (Safe) to 100 (Dangerous)
    private String protocol;
    private String domain;
    private List<String> detectedThreats;
    private String recommendation;
    private LocalDateTime timestamp;
}
