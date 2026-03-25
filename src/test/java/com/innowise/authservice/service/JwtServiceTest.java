package com.innowise.authservice.service;

import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        String secret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
        ReflectionTestUtils.setField(jwtService, "secret", secret);
        ReflectionTestUtils.setField(jwtService, "accessExp", 900000L);
        ReflectionTestUtils.setField(jwtService, "refreshExp", 604800000L);
    }

    @Test
    @DisplayName("Should generate valid Access Token")
    void shouldGenerateValidAccessToken() {
        Credentials credentials = Credentials.builder()
                .id(UUID.randomUUID())
                .email("test@innowise.com")
                .role(Role.USER)
                .build();

        String token = jwtService.generateToken(credentials, false);

        assertNotNull(token);
        assertTrue(jwtService.validate(token));
        assertEquals(credentials.getId().toString(), jwtService.extractUserId(token));
    }

    @Test
    @DisplayName("Should fail validation for malformed token")
    void shouldFailValidationForInvalidToken() {
        String invalidToken = "invalid.token.string";
        assertFalse(jwtService.validate(invalidToken));
    }

    @Test
    @DisplayName("Should generate valid Refresh Token")
    void shouldGenerateValidRefreshToken() {
        Credentials credentials = Credentials.builder()
                .id(UUID.randomUUID())
                .build();

        String token = jwtService.generateToken(credentials, true);

        assertNotNull(token);
        assertTrue(jwtService.validate(token));
    }
}
