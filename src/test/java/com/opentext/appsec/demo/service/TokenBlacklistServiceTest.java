package com.opentext.appsec.demo.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenBlacklistServiceTest {

    private TokenBlacklistService blacklistService;

    @BeforeEach
    void setUp() {
        blacklistService =
                new TokenBlacklistService();
    }

    @Test
    void shouldBlacklistActiveToken() {
        long futureExpiration =
                System.currentTimeMillis() + 60000;

        blacklistService.blacklistToken(
                "active-token",
                futureExpiration);

        assertTrue(
                blacklistService.isBlacklisted(
                        "active-token"));
    }

    @Test
    void shouldIgnoreNullAndBlankTokens() {
        blacklistService.blacklistToken(
                null,
                System.currentTimeMillis() + 60000);

        blacklistService.blacklistToken(
                " ",
                System.currentTimeMillis() + 60000);

        assertFalse(
                blacklistService.isBlacklisted(null));

        assertFalse(
                blacklistService.isBlacklisted(" "));
    }

    @Test
    void shouldRemoveExpiredToken() {
        long expiredTime =
                System.currentTimeMillis() - 1000;

        blacklistService.blacklistToken(
                "expired-token",
                expiredTime);

        assertFalse(
                blacklistService.isBlacklisted(
                        "expired-token"));

        assertFalse(
                blacklistService.isBlacklisted(
                        "expired-token"));
    }

    @Test
    void shouldReturnFalseForUnknownToken() {
        assertFalse(
                blacklistService.isBlacklisted(
                        "unknown-token"));
    }
}
