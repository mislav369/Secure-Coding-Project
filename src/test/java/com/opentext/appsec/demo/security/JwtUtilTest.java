package com.opentext.appsec.demo.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilTest {

    private static final String TEST_SECRET =
            "12345678901234567890123456789012";

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil(TEST_SECRET, 900000);
    }

    @Test
    void shouldCreateValidToken() {
        String token =
                jwtUtil.generateToken("admin", "ADMIN");

        assertTrue(jwtUtil.validateToken(token));

        assertEquals(
                "admin",
                jwtUtil.getUsernameFromToken(token));

        assertEquals(
                "ADMIN",
                jwtUtil.getRoleFromToken(token));
    }

    @Test
    void shouldRejectInvalidToken() {
        boolean valid =
                jwtUtil.validateToken("invalid.jwt.token");

        assertFalse(valid);
    }

    @Test
    void shouldRejectExpiredToken() {
        JwtUtil expiredJwtUtil =
                new JwtUtil(TEST_SECRET, -1000);

        String token =
                expiredJwtUtil.generateToken(
                        "user",
                        "USER");

        assertFalse(
                expiredJwtUtil.validateToken(token));
    }
    @Test
    void shouldGenerateTokenWithDefaultUserRole() {
        String token =
                jwtUtil.generateToken("user");

        assertTrue(jwtUtil.validateToken(token));

        assertEquals(
                "USER",
                jwtUtil.getRoleFromToken(token));
    }

    @Test
    void shouldReturnTokenExpiration() {
        String token =
                jwtUtil.generateToken("admin", "ADMIN");

        long expiration =
                jwtUtil.getExpirationMillis(token);

        assertTrue(
                expiration > System.currentTimeMillis());
    }
}