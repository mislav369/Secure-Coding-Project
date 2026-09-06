package com.opentext.appsec.demo.controller;

import com.opentext.appsec.demo.security.UrlValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@RestController
@RequestMapping("/api/url")
public class UrlFetchController {

    private final UrlValidator urlValidator;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public UrlFetchController(UrlValidator urlValidator) {
        this.urlValidator = urlValidator;
    }

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchUrl(@RequestParam String url) {
        try {
            urlValidator.validate(url);
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(e.getMessage());
        }
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return ResponseEntity.ok("Fetched OK (HTTP " + response.statusCode() + ")");
        } catch (Exception e) {
            return ResponseEntity.status(502).body("Fetch failed: " + e.getMessage());
        }
    }
}