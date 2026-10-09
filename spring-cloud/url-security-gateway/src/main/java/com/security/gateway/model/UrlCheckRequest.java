package com.security.gateway.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UrlCheckRequest {

    @NotBlank(message = "URL cannot be blank")
    private String url;
}
