package com.opentext.appsec.demo.dto;

public record TokenResponse(String accessToken, String refreshToken, String tokenType) {}
