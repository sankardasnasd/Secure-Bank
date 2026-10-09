package com.security.gateway.service;

import com.security.gateway.model.PhishingCheckResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class PhishingDetectionService {

    private final WebClient webClient;

    public PhishingDetectionService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder
                .baseUrl("http://127.0.0.1:8001")
                .build();
    }

    public Mono<PhishingCheckResponse> checkUrl(String url) {

        return webClient.post()
                .uri("/predict")
                .bodyValue(new UrlRequest(url))
                .retrieve()
                .bodyToMono(PhishingCheckResponse.class);
    }

    private record UrlRequest(String url) {
    }
}