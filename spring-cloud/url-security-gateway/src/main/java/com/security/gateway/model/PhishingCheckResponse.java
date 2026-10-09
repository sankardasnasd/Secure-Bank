package com.security.gateway.model;

import lombok.Data;

@Data
public class PhishingCheckResponse {

    private boolean success;
    private String url;
    private String result;
    private int prediction;
    private double phishing_probability;
    private double legitimate_probability;
}