package com.security.gateway.service;

import com.security.gateway.model.UrlCheckResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class UrlSecurityService {

    // Unsafe URI schemes
    private static final List<String> BLOCKED_SCHEMES = Arrays.asList(
            "javascript", "data", "file", "vbscript", "view-source", "intent", "content"
    );

    // High-risk top-level domains often associated with spam/phishing
    private static final List<String> HIGH_RISK_TLDS = Arrays.asList(
            ".xyz", ".top", ".zip", ".kim", ".gq", ".cf", ".ml", ".tk", ".work", ".click", ".country", ".link"
    );

    // IP address pattern (raw IP hosts outside local network are potential SSRF / direct node threats)
    private static final Pattern IP_HOST_PATTERN = Pattern.compile(
            "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
    );

    // XSS payload regex
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script|javascript:|onerror=|onload=|eval\\(|alert\\(|document\\.cookie|window\\.location)"
    );

    // SQL Injection payload regex
    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|drop\\s+table|delete\\s+from|or\\s+1=1|exec\\s*\\()"
    );

    // Directory Traversal regex
    private static final Pattern TRAVERSAL_PATTERN = Pattern.compile(
            "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.\\.%2f)"
    );

    // Typosquatting / phishing keyword regex
    private static final Pattern TYPOSQUATTING_PATTERN = Pattern.compile(
            "(?i)(g00gle|paypa1|micros0ft|binance-login|secure-bank-verify|account-update-login)"
    );

    public UrlCheckResponse inspectUrl(String rawUrl) {
        List<String> threats = new ArrayList<>();
        int threatScore = 0;
        String protocol = "UNKNOWN";
        String host = "UNKNOWN";

        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            threats.add("Empty or null URL string provided.");
            return buildResponse(rawUrl, false, "DANGEROUS", 100, protocol, host, threats, "Reject request immediately: Invalid URL.");
        }

        String urlToInspect = rawUrl.trim();

        // 1. Check for unsafe URI schemes
        String lowerUrl = urlToInspect.toLowerCase();
        for (String blockedScheme : BLOCKED_SCHEMES) {
            if (lowerUrl.startsWith(blockedScheme + ":")) {
                threats.add("Blocked URI scheme detected: '" + blockedScheme + "'");
                threatScore += 100;
                protocol = blockedScheme;
                break;
            }
        }

        // 2. Parse URI
        try {
            URI uri = new URI(urlToInspect);

            if (uri.getScheme() != null) {
                protocol = uri.getScheme().toLowerCase();
            }

            if (uri.getHost() != null) {
                host = uri.getHost().toLowerCase();
            } else if (urlToInspect.contains("://")) {
                String hostPart = urlToInspect.split("://")[1].split("/")[0];
                host = hostPart.split(":")[0].toLowerCase();
            }

            // 3. Dev Localhost Exception Check
            boolean isLocalhost = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);

            // Protocol Security Check (exempt localhost HTTP)
            if ("http".equalsIgnoreCase(protocol) && !isLocalhost) {
                threats.add("Unencrypted HTTP protocol used (HTTPS recommended).");
                threatScore += 15;
            } else if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol) && threatScore < 100) {
                threats.add("Non-standard web protocol: '" + protocol + "'");
                threatScore += 30;
            }

            // 4. IP Host check (Exempt localhost IP 127.0.0.1)
            if (IP_HOST_PATTERN.matcher(host).matches() && !isLocalhost) {
                threats.add("Direct external IP address used as host (Possible SSRF / Malicious Node).");
                threatScore += 35;
            }

            // 5. High Risk TLD Check
            for (String riskTld : HIGH_RISK_TLDS) {
                if (host.endsWith(riskTld)) {
                    threats.add("High-risk top-level domain detected: '" + riskTld + "'");
                    threatScore += 40;
                    break;
                }
            }

            // 6. Typosquatting Check
            if (TYPOSQUATTING_PATTERN.matcher(host).find()) {
                threats.add("Phishing / Typosquatting pattern detected in host name.");
                threatScore += 50;
            }

        } catch (Exception e) {
            threats.add("Malformed URI syntax: " + e.getMessage());
            threatScore += 50;
        }

        // 7. Payload Inspection (XSS, SQLi, Path Traversal in full URL)
        if (XSS_PATTERN.matcher(urlToInspect).find()) {
            threats.add("Cross-Site Scripting (XSS) payload detected in URL.");
            threatScore += 60;
        }

        if (SQLI_PATTERN.matcher(urlToInspect).find()) {
            threats.add("SQL Injection (SQLi) pattern detected in URL parameters.");
            threatScore += 70;
        }

        if (TRAVERSAL_PATTERN.matcher(urlToInspect).find()) {
            threats.add("Directory / Path Traversal attempt detected in URL.");
            threatScore += 50;
        }

        // Cap score at 100
        threatScore = Math.min(threatScore, 100);

        // Classify Status
        String status;
        boolean isSecure;
        String recommendation;

        if (threatScore <= 15) {
            status = "SAFE";
            isSecure = true;
            recommendation = "URL is clean and safe to navigate.";
        } else if (threatScore <= 30) {
            status = "SUSPICIOUS";
            isSecure = false;
            recommendation = "Proceed with caution. Warnings present.";
        } else {
            status = "DANGEROUS";
            isSecure = false;
            recommendation = "Block request immediately. Security threat detected.";
        }

        return buildResponse(urlToInspect, isSecure, status, threatScore, protocol, host, threats, recommendation);
    }

    private UrlCheckResponse buildResponse(String url, boolean isSecure, String status, int threatScore,
                                           String protocol, String domain, List<String> threats, String recommendation) {
        return UrlCheckResponse.builder()
                .targetUrl(url)
                .isSecure(isSecure)
                .status(status)
                .threatScore(threatScore)
                .protocol(protocol)
                .domain(domain)
                .detectedThreats(threats)
                .recommendation(recommendation)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
