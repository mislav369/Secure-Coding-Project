package com.opentext.appsec.demo.integration;

import com.opentext.appsec.demo.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Test
    void shouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(
                        get("/api/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturn403ForUserRole() throws Exception {
        String token =
                jwtUtil.generateToken("user", "USER");

        mockMvc.perform(
                        get("/api/admin/users")
                                .header(
                                        "Authorization",
                                        "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldReturn200ForAdminRole() throws Exception {
        String token =
                jwtUtil.generateToken("admin", "ADMIN");

        mockMvc.perform(
                        get("/api/admin/users")
                                .header(
                                        "Authorization",
                                        "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturn401ForExpiredToken() throws Exception {
        JwtUtil expiredJwtUtil =
                new JwtUtil(jwtSecret, -1000);

        String token =
                expiredJwtUtil.generateToken(
                        "admin",
                        "ADMIN");

        mockMvc.perform(
                        get("/api/admin/users")
                                .header(
                                        "Authorization",
                                        "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }
}
