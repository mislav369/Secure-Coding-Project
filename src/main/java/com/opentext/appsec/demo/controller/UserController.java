package com.opentext.appsec.demo.controller;

import com.opentext.appsec.demo.dto.RefreshRequest;
import com.opentext.appsec.demo.dto.TokenResponse;
import com.opentext.appsec.demo.model.RefreshToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.opentext.appsec.demo.model.User;
import com.opentext.appsec.demo.service.UserService;

import java.util.List;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

import org.springframework.web.util.HtmlUtils;

import com.opentext.appsec.demo.dto.CreateUserRequest;

import com.opentext.appsec.demo.dto.UpdateUserRequest;

import com.opentext.appsec.demo.security.JwtUtil;
import com.opentext.appsec.demo.security.TokenBlacklistService;

import com.opentext.appsec.demo.security.RefreshTokenService;

/**
 * User controller with intentional security vulnerabilities.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Log logger = LogFactory.getLog(UserController.class);

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService blacklistService;
    private final RefreshTokenService refreshTokenService;

    public UserController(
            UserService userService,
            JwtUtil jwtUtil,
            TokenBlacklistService blacklistService,
            RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.blacklistService = blacklistService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Get all users.
     */
    @Operation(summary = "Get all users", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }


    @Operation(summary = "Search users", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/search")
    public List<User> searchUsers(@Parameter(description = "Search query (unsanitized, demonstrates SQLi)") @RequestParam String query) {
        // Passes unsanitized input to service - SQL Injection
        return userService.searchUsers(query);
    }


    @Operation(summary = "Find user by username", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/find")
    public ResponseEntity<User> findUser(@Parameter(description = "Username to find (unsanitized, demonstrates SQLi)") @RequestParam String username) {
        // SQL Injection vulnerability
        User user = userService.findUserByUsername(username);
        if (user != null) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.notFound().build();
    }


        @Operation(summary = "Create a new user)",
                requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User object to create"))
        @PostMapping
        public User createUser(
                @RequestBody(required = false) CreateUserRequest request) {

            if (request == null) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.BAD_REQUEST,
                        "Empty request body"
                );
            }

            User user = new User(
                    request.username(),
                    request.password(),
                    request.email(),
                    "USER"
            );

            return userService.createUser(user);
        }


    @Operation(summary = "Update user")
    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(
            @PathVariable Long id,
            @RequestBody UpdateUserRequest request) {

        User existing = userService.getAllUsers()
                .stream()
                .filter(user -> user.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (existing == null) {
            return ResponseEntity.notFound().build();
        }

        existing.setEmail(request.email());

        if (request.password() != null && !request.password().isBlank()) {
            existing.setPassword(request.password());
        }

        userService.createUser(existing);
        return ResponseEntity.ok(existing);
    }


    @Operation(summary = "Authenticate user", security = {})
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestParam String username,
            @RequestParam String password) {

        boolean authenticated =
                userService.authenticateUser(username, password);

        if (!authenticated) {
            return ResponseEntity.status(401).build();
        }
        User user = userService.findUserByUsername(username);
        String accessToken = jwtUtil.generateToken(username, user.getRole());

        String refreshToken = refreshTokenService
                .createForLogin(username)
                .getToken();

        return ResponseEntity.ok(
                new TokenResponse(
                        accessToken,
                        refreshToken,
                        "Bearer"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody RefreshRequest request) {

        if (request == null
                || request.refreshToken() == null
                || request.refreshToken().isBlank()) {

            return ResponseEntity.status(401).build();
        }

        try {
            RefreshToken rotated =
                    refreshTokenService.rotateToken(
                            request.refreshToken());
            User user = userService.findUserByUsername(
                    rotated.getUsername());
            String accessToken = jwtUtil.generateToken(
                    rotated.getUsername(),
                    user.getRole());

            return ResponseEntity.ok(
                    new TokenResponse(
                            accessToken,
                            rotated.getToken(),
                            "Bearer"));
        } catch (IllegalArgumentException exception) {
            return ResponseEntity.status(401).build();
        }
    }



    /**
     * Logout: blacklist the provided token until its expiry.
     */
    @Operation(
            summary = "Logout and revoke tokens",
            security = {
                    @io.swagger.v3.oas.annotations.security.SecurityRequirement(
                            name = "bearerAuth")
            })
    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @RequestHeader(
                    value = "Authorization",
                    required = false) String authHeader,
            @RequestBody(required = false) RefreshRequest request) {

        if (authHeader != null
                && authHeader.startsWith("Bearer ")) {

            String accessToken = authHeader.substring(7);

            try {
                long expiration =
                        jwtUtil.getExpirationMillis(accessToken);

                blacklistService.blacklistToken(
                        accessToken,
                        expiration);

            } catch (Exception exception) {
                logger.warn(
                        "Failed to parse token during logout",
                        exception);
            }
        }

        if (request != null
                && request.refreshToken() != null
                && !request.refreshToken().isBlank()) {

            refreshTokenService.revokeFamilyByToken(
                    request.refreshToken());
        }

        return ResponseEntity.ok(
                "Logged out and tokens revoked");
    }

    //@GetMapping("/search-vuln")
    //public List<User> searchUsersVulnerable(@RequestParam String query) {
        //return userService.searchUsersVulnerable(query);
    //}


    @Operation(summary = "Welcome page", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/welcome")
    public String welcome(@Parameter(description = "Name to welcome (not escaped)") @RequestParam String name) {
        // Cross-Site Scripting (XSS) vulnerability - no HTML escaping
        // Return a longer, more interesting welcome HTML for the demo
        return "<html><body>" +
                "<div style=\"font-family:Arial,Helvetica,sans-serif;max-width:800px;margin:0 auto;\">" +
                "<h1 style=\"color:#1f2937;\">Welcome, " + HtmlUtils.htmlEscape(name) + "!</h1>" +
                "<p style=\"color:#374151;\">Glad to see you back. Here's a quick summary of your demo account and recent activity — useful for demoing dashboards and data visualizations.</p>" +
                "<ul style=\"color:#374151;\">" +
                "<li><strong>Payments:</strong> You have sample payment methods (credit cards and PayPal) seeded for demo purposes.</li>" +
                "<li><strong>Transactions:</strong> Example transactions are available. Use the Payments view to inspect or simulate charges.</li>" +
                "<li><strong>Security note:</strong> This demo intentionally stores sensitive fields in plain text — do not replicate this in production.</li>" +
                "</ul>" +
                "<h3 style=\"color:#111827;margin-top:18px;\">Tips & next steps</h3>" +
                "<ol style=\"color:#374151;\">" +
                "<li>Try creating a new user via the Register button and then add a payment method.</li>" +
                "<li>Use the debug endpoints to explore seeded data (this app intentionally exposes sensitive data for scanning exercises).</li>" +
                "<li>Check the Payments page to simulate charges and then view the transactions list.</li>" +
                "</ol>" +
                "<p style=\"color:#6b7280; font-size:0.9em; margin-top:12px;\">(This welcome message is intentionally reflective and not escaped to demonstrate XSS findings during security scans.)</p>" +
                "</div></body></html>";

    }


    @Operation(summary = "User profile", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/{id}/profile")
    public String getUserProfile(@Parameter(description = "User id") @PathVariable Long id,
                                 @Parameter(description = "Optional message reflected into HTML (not escaped)") @RequestParam(required = false) String message) {
        // XSS vulnerability - unsanitized user input reflected in HTML
        return "<html><body><h1>User Profile #" + id + "</h1>" +
                (message != null ? "<div class='message'>" + message + "</div>" : "") +
                "</body></html>";
    }
}
