package com.opentext.appsec.demo.controller;

import com.opentext.appsec.demo.dto.CreateUserRequest;
import com.opentext.appsec.demo.dto.RefreshRequest;
import com.opentext.appsec.demo.dto.TokenResponse;
import com.opentext.appsec.demo.dto.UpdateUserRequest;
import com.opentext.appsec.demo.model.RefreshToken;
import com.opentext.appsec.demo.model.User;
import com.opentext.appsec.demo.security.JwtUtil;
import com.opentext.appsec.demo.security.RefreshTokenService;
import com.opentext.appsec.demo.security.TokenBlacklistService;
import com.opentext.appsec.demo.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private TokenBlacklistService blacklistService;

    @Mock
    private RefreshTokenService refreshTokenService;

    private UserController controller;

    @BeforeEach
    void setUp() {
        controller = new UserController(
                userService,
                jwtUtil,
                blacklistService,
                refreshTokenService);
    }

    @Test
    void shouldGetSearchAndFindUsers() {
        User user = new User(
                "alice",
                "password",
                "alice@example.com",
                "USER");

        when(userService.getAllUsers())
                .thenReturn(List.of(user));

        when(userService.searchUsers("alice"))
                .thenReturn(List.of(user));

        when(userService.findUserByUsername("alice"))
                .thenReturn(user);

        assertEquals(
                1,
                controller.getAllUsers().size());

        assertEquals(
                1,
                controller.searchUsers("alice").size());

        ResponseEntity<User> response =
                controller.findUser("alice");

        assertEquals(
                200,
                response.getStatusCode().value());

        assertEquals(
                "alice",
                response.getBody().getUsername());
    }

    @Test
    void shouldReturnNotFoundWhenUserIsMissing() {
        when(userService.findUserByUsername("missing"))
                .thenReturn(null);

        ResponseEntity<User> response =
                controller.findUser("missing");

        assertEquals(
                404,
                response.getStatusCode().value());
    }

    @Test
    void shouldCreateUser() {
        CreateUserRequest request =
                new CreateUserRequest(
                        "newuser",
                        "password",
                        "newuser@example.com");

        when(userService.createUser(any(User.class)))
                .thenAnswer(invocation ->
                        invocation.getArgument(0));

        User created = controller.createUser(request);

        assertEquals("newuser", created.getUsername());
        assertEquals("USER", created.getRole());
    }

    @Test
    void shouldRejectEmptyCreateRequest() {
        assertThrows(
                ResponseStatusException.class,
                () -> controller.createUser(null));
    }

    @Test
    void shouldUpdateExistingUser() {
        User existing = new User(
                "alice",
                "oldPassword",
                "old@example.com",
                "USER");

        existing.setId(1L);

        when(userService.getAllUsers())
                .thenReturn(List.of(existing));

        ResponseEntity<User> response =
                controller.updateUser(
                        1L,
                        new UpdateUserRequest(
                                "new@example.com",
                                "newPassword"));

        assertEquals(
                200,
                response.getStatusCode().value());

        assertNotNull(response.getBody());

        assertEquals(
                "new@example.com",
                response.getBody().getEmail());

        verify(userService).createUser(existing);
    }

    @Test
    void shouldReturnNotFoundWhenUpdatingMissingUser() {
        when(userService.getAllUsers())
                .thenReturn(List.of());

        ResponseEntity<User> response =
                controller.updateUser(
                        99L,
                        new UpdateUserRequest(
                                "new@example.com",
                                "password"));

        assertEquals(
                404,
                response.getStatusCode().value());
    }

    @Test
    void shouldLoginAndReturnTokens() {
        User user = new User(
                "admin",
                "encodedPassword",
                "admin@example.com",
                "ADMIN");

        RefreshToken refreshToken =
                new RefreshToken(
                        "refresh-token",
                        "admin",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        when(userService.authenticateUser(
                "admin",
                "admin123"))
                .thenReturn(true);

        when(userService.findUserByUsername("admin"))
                .thenReturn(user);

        when(jwtUtil.generateToken("admin", "ADMIN"))
                .thenReturn("access-token");

        when(refreshTokenService.createForLogin("admin"))
                .thenReturn(refreshToken);

        ResponseEntity<TokenResponse> response =
                controller.login(
                        "admin",
                        "admin123");

        assertEquals(
                200,
                response.getStatusCode().value());

        assertNotNull(response.getBody());
        assertEquals(
                "access-token",
                response.getBody().accessToken());
        assertEquals(
                "refresh-token",
                response.getBody().refreshToken());
    }

    @Test
    void shouldRejectInvalidLogin() {
        when(userService.authenticateUser(
                "admin",
                "wrong"))
                .thenReturn(false);

        ResponseEntity<TokenResponse> response =
                controller.login(
                        "admin",
                        "wrong");

        assertEquals(
                401,
                response.getStatusCode().value());
    }

    @Test
    void shouldRotateRefreshToken() {
        User user = new User(
                "user",
                "encodedPassword",
                "user@example.com",
                "USER");

        RefreshToken rotatedToken =
                new RefreshToken(
                        "new-refresh-token",
                        "user",
                        "family-1",
                        Instant.now().plusSeconds(3600));

        when(refreshTokenService.rotateToken("old-refresh-token"))
                .thenReturn(rotatedToken);

        when(userService.findUserByUsername("user"))
                .thenReturn(user);

        when(jwtUtil.generateToken("user", "USER"))
                .thenReturn("new-access-token");

        ResponseEntity<TokenResponse> response =
                controller.refresh(
                        new RefreshRequest(
                                "old-refresh-token"));

        assertEquals(
                200,
                response.getStatusCode().value());

        assertNotNull(response.getBody());
        assertEquals(
                "new-access-token",
                response.getBody().accessToken());
        assertEquals(
                "new-refresh-token",
                response.getBody().refreshToken());
    }

    @Test
    void shouldRejectInvalidRefreshRequests() {
        assertEquals(
                401,
                controller.refresh(null)
                        .getStatusCode()
                        .value());

        assertEquals(
                401,
                controller.refresh(
                                new RefreshRequest(""))
                        .getStatusCode()
                        .value());

        when(refreshTokenService.rotateToken("invalid"))
                .thenThrow(
                        new IllegalArgumentException(
                                "Invalid refresh token"));

        assertEquals(
                401,
                controller.refresh(
                                new RefreshRequest("invalid"))
                        .getStatusCode()
                        .value());
    }

    @Test
    void shouldLogoutAndRevokeTokens() {
        when(jwtUtil.getExpirationMillis("access-token"))
                .thenReturn(123456789L);

        ResponseEntity<String> response =
                controller.logout(
                        "Bearer access-token",
                        new RefreshRequest("refresh-token"));

        assertEquals(
                200,
                response.getStatusCode().value());

        verify(blacklistService)
                .blacklistToken(
                        "access-token",
                        123456789L);

        verify(refreshTokenService)
                .revokeFamilyByToken(
                        "refresh-token");
    }

    @Test
    void shouldEscapeWelcomeNameAndRenderProfile() {
        String welcome =
                controller.welcome("<script>alert(1)</script>");

        assertTrue(
                welcome.contains(
                        "&lt;script&gt;alert(1)&lt;/script&gt;"));

        String profileWithMessage =
                controller.getUserProfile(
                        1L,
                        "Hello");

        assertTrue(
                profileWithMessage.contains("Hello"));

        String profileWithoutMessage =
                controller.getUserProfile(
                        1L,
                        null);

        assertTrue(
                profileWithoutMessage.contains(
                        "User Profile #1"));
    }
}