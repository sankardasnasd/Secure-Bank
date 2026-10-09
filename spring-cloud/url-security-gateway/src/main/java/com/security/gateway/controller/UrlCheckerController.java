package com.security.gateway.controller;

import com.security.gateway.model.UrlCheckRequest;
import com.security.gateway.model.UrlCheckResponse;
import com.security.gateway.service.UrlSecurityService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/url-scanner")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class UrlCheckerController {

    private final UrlSecurityService urlSecurityService;

    public UrlCheckerController(UrlSecurityService urlSecurityService) {
        this.urlSecurityService = urlSecurityService;
    }

    @PostMapping("/check")
    public Mono<ResponseEntity<UrlCheckResponse>> checkUrl(@Valid @RequestBody UrlCheckRequest request) {
        UrlCheckResponse response = urlSecurityService.inspectUrl(request.getUrl());
        if (!response.getIsSecure() || response.getThreatScore() > 30) {
            return Mono.just(ResponseEntity.status(403).body(response));
        }
        return Mono.just(ResponseEntity.ok(response));
    }

    @GetMapping("/health")
    public Mono<ResponseEntity<Map<String, Object>>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("service", "Spring Cloud URL Security Gateway");
        health.put("status", "ACTIVE");
        health.put("description", "Pre-routing security scanner active.");
        return Mono.just(ResponseEntity.ok(health));
    }
}
