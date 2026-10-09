package com.security.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.security.gateway.model.PhishingCheckResponse;
import com.security.gateway.model.UrlCheckResponse;
import com.security.gateway.service.PhishingDetectionService;
import com.security.gateway.service.UrlSecurityService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class UrlSecurityGatewayFilterFactory
        extends AbstractGatewayFilterFactory<UrlSecurityGatewayFilterFactory.Config> {

    private final UrlSecurityService urlSecurityService;
    private final PhishingDetectionService phishingDetectionService;
    private final ObjectMapper objectMapper;

    public UrlSecurityGatewayFilterFactory(
            UrlSecurityService urlSecurityService,
            PhishingDetectionService phishingDetectionService) {

        super(Config.class);

        this.urlSecurityService = urlSecurityService;
        this.phishingDetectionService = phishingDetectionService;

        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }

    @Override
    public String name() {
        return "UrlSecurityGateway";
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();

            String fullRequestUrl = request.getURI().toString();

            String targetUrlParam =
                    request.getQueryParams().getFirst("url");

            String urlToInspect =
                    (targetUrlParam != null &&
                            !targetUrlParam.trim().isEmpty())
                            ? targetUrlParam
                            : fullRequestUrl;

            // Existing rule-based URL security check
            UrlCheckResponse securityAssessment =
                    urlSecurityService.inspectUrl(urlToInspect);

            // Existing security rules
            if (!securityAssessment.getIsSecure()
                    || securityAssessment.getThreatScore() > 30) {

                return writeJsonResponse(
                        exchange.getResponse(),
                        HttpStatus.FORBIDDEN,
                        securityAssessment
                );
            }

            // ML Phishing Detection
            return phishingDetectionService
                    .checkUrl(urlToInspect)
                    .flatMap(phishingResult -> {

                        if ("PHISHING".equalsIgnoreCase(
                                phishingResult.getResult())) {

                            return writeJsonResponse(
                                    exchange.getResponse(),
                                    HttpStatus.FORBIDDEN,
                                    phishingResult
                            );
                        }

                        return chain.filter(exchange);
                    })
                    .onErrorResume(error -> {

                        System.out.println(
                                "Phishing service error: "
                                        + error.getMessage()
                        );

                        // If ML service is unavailable,
                        // continue with existing security check.
                        return chain.filter(exchange);
                    });
        };
    }

    private Mono<Void> writeJsonResponse(
            ServerHttpResponse response,
            HttpStatus status,
            Object responseObject) {

        response.setStatusCode(status);
        response.getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);

        try {

            byte[] responseBytes =
                    objectMapper.writeValueAsString(responseObject)
                            .getBytes(StandardCharsets.UTF_8);

            DataBuffer buffer =
                    response.bufferFactory()
                            .wrap(responseBytes);

            return response.writeWith(
                    Mono.just(buffer)
            );

        } catch (Exception e) {

            return response.setComplete();
        }
    }

    public static class Config {
    }
}