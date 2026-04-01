package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.RefreshToken;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.UserNotFoundException;
import com.innowise.authservice.repository.CredentialsRepository;
import com.innowise.authservice.repository.RefreshTokenRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private CredentialsRepository credentialsRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    @DisplayName("Register saves credentials when email is not taken")
    void registerSavesCredentialsWhenEmailIsNotTaken() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");

        when(credentialsRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashedPassword");

        authService.register(request);

        verify(credentialsRepository).save(any(Credentials.class));
    }

    @Test
    @DisplayName("Register throws AuthException when email is already taken")
    void registerThrowsAuthExceptionWhenEmailIsAlreadyTaken() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");

        when(credentialsRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.of(new Credentials()));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining(request.getEmail());
    }

    @Test
    @DisplayName("Login returns tokens and saves refresh token when credentials are valid")
    void loginReturnsTokensWhenCredentialsAreValid() {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");

        Credentials credentials = Credentials.builder()
                .userId(UUID.randomUUID())
                .email(request.getEmail())
                .passwordHash("hashedPassword")
                .role(Role.USER)
                .build();

        ReflectionTestUtils.setField(authService, "refreshExp", 86400000L);

        when(credentialsRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())).thenReturn(true);
        when(jwtService.generateToken(credentials, false)).thenReturn("accessToken");
        when(jwtService.generateToken(credentials, true)).thenReturn("refreshToken");

        AuthResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getRefreshToken()).isEqualTo("refreshToken");
        verify(refreshTokenRepository).revokeAllByCredentials(credentials);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Login throws UserNotFoundException when email does not exist")
    void loginThrowsUserNotFoundExceptionWhenEmailDoesNotExist() {
        AuthRequest request = new AuthRequest();
        request.setEmail("unknown@example.com");
        request.setPassword("password");

        when(credentialsRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    @DisplayName("Login throws AuthException when password is invalid")
    void loginThrowsAuthExceptionWhenPasswordIsInvalid() {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrongPassword");

        Credentials credentials = Credentials.builder()
                .email(request.getEmail())
                .passwordHash("hashedPassword")
                .role(Role.USER)
                .build();

        when(credentialsRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid password");
    }

    @Test
    @DisplayName("Refresh returns new access token and rotates refresh token when token is valid")
    void refreshReturnsNewAccessTokenWhenRefreshTokenIsValid() {
        Credentials credentials = Credentials.builder()
                .userId(UUID.randomUUID())
                .email("test@example.com")
                .role(Role.USER)
                .build();

        RefreshToken stored = RefreshToken.builder()
                .token("refreshToken")
                .credentials(credentials)
                .expiresAt(Instant.now().plusSeconds(3600))
                .revoked(false)
                .build();

        ReflectionTestUtils.setField(authService, "refreshExp", 86400000L);

        when(jwtService.validateRefresh("refreshToken")).thenReturn(true);
        when(refreshTokenRepository.findByToken("refreshToken")).thenReturn(Optional.of(stored));
        when(jwtService.generateToken(credentials, false)).thenReturn("newAccessToken");
        when(jwtService.generateToken(credentials, true)).thenReturn("newRefreshToken");

        String result = authService.refresh("refreshToken");

        assertThat(result).isEqualTo("newAccessToken");
        assertThat(stored.isRevoked()).isTrue();
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Refresh throws TokenException when JWT signature is invalid")
    void refreshThrowsTokenExceptionWhenRefreshTokenIsInvalid() {
        when(jwtService.validateRefresh("invalidToken")).thenReturn(false);

        assertThatThrownBy(() -> authService.refresh("invalidToken"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    @Test
    @DisplayName("Refresh throws TokenException when refresh token is not found in database")
    void refreshThrowsTokenExceptionWhenRefreshTokenNotFoundInDatabase() {
        when(jwtService.validateRefresh("ghostToken")).thenReturn(true);
        when(refreshTokenRepository.findByToken("ghostToken")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("ghostToken"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("Refresh token not found");
    }

    @Test
    @DisplayName("Refresh throws TokenException when refresh token is revoked")
    void refreshThrowsTokenExceptionWhenRefreshTokenIsRevoked() {
        Credentials credentials = Credentials.builder()
                .userId(UUID.randomUUID())
                .role(Role.USER)
                .build();

        RefreshToken revoked = RefreshToken.builder()
                .token("revokedToken")
                .credentials(credentials)
                .expiresAt(Instant.now().plusSeconds(3600))
                .revoked(true)
                .build();

        when(jwtService.validateRefresh("revokedToken")).thenReturn(true);
        when(refreshTokenRepository.findByToken("revokedToken")).thenReturn(Optional.of(revoked));

        assertThatThrownBy(() -> authService.refresh("revokedToken"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("Refresh token has been revoked");
    }

    @Test
    @DisplayName("Refresh throws TokenException when refresh token is expired in database")
    void refreshThrowsTokenExceptionWhenRefreshTokenIsExpiredInDatabase() {
        Credentials credentials = Credentials.builder()
                .userId(UUID.randomUUID())
                .role(Role.USER)
                .build();

        RefreshToken expired = RefreshToken.builder()
                .token("expiredToken")
                .credentials(credentials)
                .expiresAt(Instant.now().minusSeconds(3600))
                .revoked(false)
                .build();

        when(jwtService.validateRefresh("expiredToken")).thenReturn(true);
        when(refreshTokenRepository.findByToken("expiredToken")).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> authService.refresh("expiredToken"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("Refresh token has expired");
    }

    @Test
    @DisplayName("Logout revokes refresh token when token exists")
    void logoutRevokesRefreshTokenWhenTokenExists() {
        RefreshToken stored = RefreshToken.builder()
                .token("refreshToken")
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByToken("refreshToken")).thenReturn(Optional.of(stored));

        authService.logout("refreshToken");

        assertThat(stored.isRevoked()).isTrue();
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    @DisplayName("Logout throws TokenException when token does not exist")
    void logoutThrowsTokenExceptionWhenTokenDoesNotExist() {
        when(refreshTokenRepository.findByToken("unknownToken")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.logout("unknownToken"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("Refresh token not found");
    }

    @Test
    @DisplayName("Validate returns ValidateResponse with valid=true when token is valid")
    void validateReturnsValidResponseWhenTokenIsValid() {
        UUID userId = UUID.randomUUID();
        ValidateResponse expected = new ValidateResponse(true, userId.toString(), Role.USER);

        when(jwtService.validateAndExtract("validToken")).thenReturn(expected);

        ValidateResponse result = authService.validate("validToken");

        assertThat(result.isValid()).isTrue();
        assertThat(result.getUserId()).isEqualTo(userId.toString());
        assertThat(result.getRole()).isEqualTo(Role.USER);
    }

    @Test
    @DisplayName("Validate returns ValidateResponse with valid=false when token is invalid")
    void validateReturnsInvalidResponseWhenTokenIsInvalid() {
        ValidateResponse expected = new ValidateResponse(false, null, null);

        when(jwtService.validateAndExtract("invalidToken")).thenReturn(expected);

        ValidateResponse result = authService.validate("invalidToken");

        assertThat(result.isValid()).isFalse();
        assertThat(result.getUserId()).isNull();
        assertThat(result.getRole()).isNull();
    }

    @Test
    @DisplayName("Assign admin role updates role to admin")
    void assignAdminRoleUpdatesRoleToAdmin() {
        UUID userId = UUID.randomUUID();
        Credentials credentials = Credentials.builder()
                .userId(userId)
                .role(Role.USER)
                .build();

        when(credentialsRepository.findByUserId(userId)).thenReturn(Optional.of(credentials));

        authService.assignAdminRole(userId);

        assertThat(credentials.getRole()).isEqualTo(Role.ADMIN);
        verify(credentialsRepository).save(credentials);
    }

    @Test
    @DisplayName("Assign admin role throws UserNotFoundException when user does not exist")
    void assignAdminRoleThrowsUserNotFoundExceptionWhenUserDoesNotExist() {
        UUID userId = UUID.randomUUID();

        when(credentialsRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.assignAdminRole(userId))
                .isInstanceOf(UserNotFoundException.class);
    }
}
