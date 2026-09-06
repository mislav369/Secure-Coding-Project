package com.opentext.appsec.demo.security;

import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    @Test
    void tokenLifecycle() {
        JwtUtil jwtUtil = new JwtUtil("test-secret-that-is-at-least-32-bytes-long!!", 86400000L);
        String token = jwtUtil.generateToken("alice");

        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));
        assertEquals("alice", jwtUtil.getUsernameFromToken(token));
    }
}
