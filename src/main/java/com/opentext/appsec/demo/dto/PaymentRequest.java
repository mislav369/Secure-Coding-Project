package com.opentext.appsec.demo.dto;

public record PaymentRequest(
        Long userId,
        String type,
        String cardNumber,
        String cardExpiry,
        String cvv,
        String paypalEmail
) {}
