package com.opentext.appsec.demo.security;

import com.opentext.appsec.demo.model.RefreshToken;
import com.opentext.appsec.demo.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final long refreshExpirationMs;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-expiration-ms}") long refreshExpirationMs) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    public RefreshToken createForLogin(String username) {
        String familyId = UUID.randomUUID().toString();
        return createToken(username, familyId);
    }

    public synchronized RefreshToken rotateToken(String tokenValue) {
        RefreshToken oldToken = refreshTokenRepository
                .findByToken(tokenValue)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Invalid refresh token"));

        if (oldToken.isRevoked()) {
            revokeFamily(oldToken.getFamilyId());

            throw new IllegalArgumentException(
                    "Refresh token reuse detected");
        }

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            oldToken.setRevoked(true);
            refreshTokenRepository.save(oldToken);

            throw new IllegalArgumentException(
                    "Refresh token has expired");
        }

        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);

        return createToken(
                oldToken.getUsername(),
                oldToken.getFamilyId());
    }

    public void revokeFamilyByToken(String rawToken) {
        refreshTokenRepository.findByToken(rawToken)
                .ifPresent(token ->
                        revokeFamily(token.getFamilyId()));
    }

    private RefreshToken createToken(String username, String familyId) {
        String token = generateRandomToken();
        Instant expiry = Instant.now().plusMillis(refreshExpirationMs);
        RefreshToken refreshToken = new RefreshToken(token, username, familyId, expiry);
        return refreshTokenRepository.save(refreshToken);
    }

    private String generateRandomToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void revokeFamily(String familyId) {
        List<RefreshToken> familyTokens =
                refreshTokenRepository
                        .findAllByFamilyId(familyId);

        familyTokens.forEach(token ->
                token.setRevoked(true));

        refreshTokenRepository.saveAll(familyTokens);
    }
}