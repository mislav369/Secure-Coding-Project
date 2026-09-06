package com.opentext.appsec.demo.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityModelTest {

    @Test
    void shouldStoreRefreshTokenData() {
        Instant expiry =
                Instant.now().plusSeconds(3600);

        RefreshToken token =
                new RefreshToken();

        token.setToken("refresh-token");
        token.setUsername("admin");
        token.setFamilyId("family-1");
        token.setExpiryDate(expiry);
        token.setRevoked(true);

        assertNull(token.getId());
        assertEquals(
                "refresh-token",
                token.getToken());
        assertEquals(
                "admin",
                token.getUsername());
        assertEquals(
                "family-1",
                token.getFamilyId());
        assertEquals(
                expiry,
                token.getExpiryDate());
        assertTrue(token.isRevoked());
    }

    @Test
    void shouldStoreUserProfileData() {
        UserProfile profile =
                new UserProfile();

        profile.setUsername("user");
        profile.setEmail("user@example.com");
        profile.setRole("USER");

        assertEquals(
                "user",
                profile.getUsername());
        assertEquals(
                "user@example.com",
                profile.getEmail());
        assertEquals(
                "USER",
                profile.getRole());

        assertTrue(
                profile.toString()
                        .contains("user@example.com"));
    }

    @Test
    void shouldStoreUserData() {
        User user = new User();

        user.setId(1L);
        user.setUsername("admin");
        user.setPassword("encodedPassword");
        user.setEmail("admin@example.com");
        user.setRole("ADMIN");

        assertEquals(1L, user.getId());
        assertEquals("admin", user.getUsername());
        assertEquals(
                "encodedPassword",
                user.getPassword());
        assertEquals(
                "admin@example.com",
                user.getEmail());
        assertEquals("ADMIN", user.getRole());

        assertFalse(User.getApiKey().isBlank());
    }
}
