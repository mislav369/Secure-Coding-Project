package com.opentext.appsec.demo.security;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;

@Component
public class UrlValidator {

    private static final List<String> BLOCKED_HOSTS = List.of(
            "127.0.0.1",
            "localhost",
            "169.254.169.254",
            "10.0.0.0/8",
            "192.168.0.0/16"
    );

    public void validate(String urlString) {
        URI uri = URI.create(urlString);
        String host = uri.getHost();
        if (BLOCKED_HOSTS.contains(host)) {
            throw new SecurityException("SSRF ALERT");
        }
    }
}