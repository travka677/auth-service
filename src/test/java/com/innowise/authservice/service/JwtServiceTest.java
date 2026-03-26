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
    @DisplayName("Extract user id throws TokenException when token has expired")
    void extractUserIdThrowsTokenExceptionWhenTokenHasExpired() {
        ReflectionTestUtils.setField(jwtService, "accessExp", -1000L);
        String expiredToken = jwtService.generateToken(credentials, false);

        assertThatThrownBy(() -> jwtService.extractUserId(expiredToken))
                .isInstanceOf(TokenException.class)
                .hasMessage("Token has expired");
    }

    @Test
    @DisplayName("Extract user id throws TokenException when token is malformed")
    void extractUserIdThrowsTokenExceptionWhenTokenIsMalformed() {
        assertThatThrownBy(() -> jwtService.extractUserId("malformed.token.here"))
                .isInstanceOf(TokenException.class)
                .hasMessage("Token is malformed");
    }

    @Test
    @DisplayName("Extract user id throws TokenException when token is empty")
    void extractUserIdThrowsTokenExceptionWhenTokenIsEmpty() {
        assertThatThrownBy(() -> jwtService.extractUserId(""))
                .isInstanceOf(TokenException.class)
                .hasMessage("Token is empty or null");
    }

    @Test
    @DisplayName("Extract user id throws TokenException when token signature is invalid")
    void extractUserIdThrowsTokenExceptionWhenTokenSignatureIsInvalid() {
        String validToken = jwtService.generateToken(credentials, false);
        String tamperedToken = validToken.substring(0, validToken.lastIndexOf('.') + 1) + "invalidsignature";

        assertThatThrownBy(() -> jwtService.extractUserId(tamperedToken))
                .isInstanceOf(TokenException.class)
                .hasMessage("Token signature is invalid");
    }
}
