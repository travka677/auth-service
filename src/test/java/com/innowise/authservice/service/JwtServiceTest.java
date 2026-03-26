package com.innowise.authservice.service;

import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.TokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private JwtService jwtService;

    private Credentials credentials;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret",
                "dGVzdFNlY3JldEtleVRoYXRJc0xvbmdFbm91Z2hGb3JITWFD");
        ReflectionTestUtils.setField(jwtService, "accessExp", 900000L);
        ReflectionTestUtils.setField(jwtService, "refreshExp", 86400000L);

        credentials = Credentials.builder()
                .userId(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .role(Role.USER)
                .build();
    }

    @Test
    @DisplayName("Generate access token returns non null token")
    void generateAccessTokenReturnsNonNullToken() {
        String token = jwtService.generateToken(credentials, false);

        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("Generate refresh token returns non null token")
    void generateRefreshTokenReturnsNonNullToken() {
        String token = jwtService.generateToken(credentials, true);

        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("Validate returns true for valid access token")
    void validateReturnsTrueForValidAccessToken() {
        String token = jwtService.generateToken(credentials, false);

        assertThat(jwtService.validate(token)).isTrue();
    }

    @Test
    @DisplayName("Validate returns false for refresh token")
    void validateReturnsFalseForRefreshToken() {
        String token = jwtService.generateToken(credentials, true);

        assertThat(jwtService.validate(token)).isFalse();
    }

    @Test
    @DisplayName("Validate returns false for invalid token")
    void validateReturnsFalseForInvalidToken() {
        assertThat(jwtService.validate("invalidToken")).isFalse();
    }

    @Test
    @DisplayName("Validate refresh returns true for valid refresh token")
    void validateRefreshReturnsTrueForValidRefreshToken() {
        String token = jwtService.generateToken(credentials, true);

        assertThat(jwtService.validateRefresh(token)).isTrue();
    }

    @Test
    @DisplayName("Validate refresh returns false for access token")
    void validateRefreshReturnsFalseForAccessToken() {
        String token = jwtService.generateToken(credentials, false);

        assertThat(jwtService.validateRefresh(token)).isFalse();
    }

    @Test
    @DisplayName("Extract user id returns correct user id from token")
    void extractUserIdReturnsCorrectUserIdFromToken() {
        String token = jwtService.generateToken(credentials, false);

        String extractedUserId = jwtService.extractUserId(token);

        assertThat(extractedUserId).isEqualTo(credentials.getUserId().toString());
    }

    @Test
    @DisplayName("Extract user id throws TokenException for invalid token")
    void extractUserIdThrowsTokenExceptionForInvalidToken() {
        assertThatThrownBy(() -> jwtService.extractUserId("invalidToken"))
                .isInstanceOf(TokenException.class);
    }
}
