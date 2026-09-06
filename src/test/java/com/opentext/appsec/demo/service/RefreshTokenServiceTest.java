package com.opentext.appsec.demo.security;

import com.opentext.appsec.demo.model.RefreshToken;
import com.opentext.appsec.demo.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService =
                new RefreshTokenService(
                        refreshTokenRepository,
                        604800000);
    }

    @Test
    void shouldCreateRefreshTokenForLogin() {
        when(refreshTokenRepository.save(
                any(RefreshToken.class)))
                .thenAnswer(invocation ->
                        invocation.getArgument(0));

        RefreshToken token =
                refreshTokenService.createForLogin("user");

        assertNotNull(token);
        assertEquals("user", token.getUsername());
        assertFalse(token.getToken().isBlank());
        assertFalse(token.getFamilyId().isBlank());
        assertFalse(token.isRevoked());

        assertTrue(
                token.getExpiryDate()
                        .isAfter(Instant.now()));
    }

    @Test
    void shouldRotateValidRefreshToken() {
        RefreshToken oldToken =
                new RefreshToken(
                        "old-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        when(refreshTokenRepository.findByToken("old-token"))
                .thenReturn(Optional.of(oldToken));

        when(refreshTokenRepository.save(
                any(RefreshToken.class)))
                .thenAnswer(invocation ->
                        invocation.getArgument(0));

        RefreshToken newToken =
                refreshTokenService.rotateToken("old-token");

        assertTrue(oldToken.isRevoked());
        assertEquals(
                "user",
                newToken.getUsername());
        assertEquals(
                "family-1",
                newToken.getFamilyId());
        assertFalse(newToken.isRevoked());

        assertNotEquals(
                "old-token",
                newToken.getToken());
    }

    @Test
    void shouldRejectUnknownRefreshToken() {
        when(refreshTokenRepository.findByToken("unknown"))
                .thenReturn(Optional.empty());

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> refreshTokenService
                                .rotateToken("unknown"));

        assertEquals(
                "Invalid refresh token",
                exception.getMessage());
    }

    @Test
    void shouldRejectExpiredRefreshToken() {
        RefreshToken expiredToken =
                new RefreshToken(
                        "expired-token",
                        "user",
                        "family-1",
                        Instant.now().minusSeconds(60));

        when(refreshTokenRepository
                .findByToken("expired-token"))
                .thenReturn(Optional.of(expiredToken));

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> refreshTokenService
                                .rotateToken("expired-token"));

        assertEquals(
                "Refresh token has expired",
                exception.getMessage());

        assertTrue(expiredToken.isRevoked());

        verify(refreshTokenRepository)
                .save(expiredToken);
    }

    @Test
    void shouldRevokeFamilyWhenTokenIsReused() {
        RefreshToken reusedToken =
                new RefreshToken(
                        "reused-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        reusedToken.setRevoked(true);

        RefreshToken secondToken =
                new RefreshToken(
                        "second-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        when(refreshTokenRepository
                .findByToken("reused-token"))
                .thenReturn(Optional.of(reusedToken));

        when(refreshTokenRepository
                .findAllByFamilyId("family-1"))
                .thenReturn(
                        List.of(
                                reusedToken,
                                secondToken));

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> refreshTokenService
                                .rotateToken("reused-token"));

        assertEquals(
                "Refresh token reuse detected",
                exception.getMessage());

        assertTrue(reusedToken.isRevoked());
        assertTrue(secondToken.isRevoked());

        verify(refreshTokenRepository)
                .saveAll(
                        List.of(
                                reusedToken,
                                secondToken));
    }

    @Test
    void shouldRevokeFamilyByToken() {
        RefreshToken firstToken =
                new RefreshToken(
                        "first-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        RefreshToken secondToken =
                new RefreshToken(
                        "second-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        when(refreshTokenRepository
                .findByToken("first-token"))
                .thenReturn(Optional.of(firstToken));

        when(refreshTokenRepository
                .findAllByFamilyId("family-1"))
                .thenReturn(
                        List.of(
                                firstToken,
                                secondToken));

        refreshTokenService
                .revokeFamilyByToken("first-token");

        assertTrue(firstToken.isRevoked());
        assertTrue(secondToken.isRevoked());

        verify(refreshTokenRepository)
                .saveAll(
                        List.of(
                                firstToken,
                                secondToken));
    }
}
