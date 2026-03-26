package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.UserNotFoundException;
import com.innowise.authservice.repository.CredentialsRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

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
    @DisplayName("Login returns tokens when credentials are valid")
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

        when(credentialsRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())).thenReturn(true);
        when(jwtService.generateToken(credentials, false)).thenReturn("accessToken");
        when(jwtService.generateToken(credentials, true)).thenReturn("refreshToken");

        AuthResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getRefreshToken()).isEqualTo("refreshToken");
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
    @DisplayName("Refresh returns new access token when refresh token is valid")
    void refreshReturnsNewAccessTokenWhenRefreshTokenIsValid() {
        UUID userId = UUID.randomUUID();
        Credentials credentials = Credentials.builder()
                .userId(userId)
                .email("test@example.com")
                .role(Role.USER)
                .build();

        when(jwtService.validateRefresh("refreshToken")).thenReturn(true);
        when(jwtService.extractUserId("refreshToken")).thenReturn(userId.toString());
        when(credentialsRepository.findByUserId(userId)).thenReturn(Optional.of(credentials));
        when(jwtService.generateToken(credentials, false)).thenReturn("newAccessToken");

        String result = authService.refresh("refreshToken");

        assertThat(result).isEqualTo("newAccessToken");
    }

    @Test
    @DisplayName("Refresh throws TokenException when refresh token is invalid")
    void refreshThrowsTokenExceptionWhenRefreshTokenIsInvalid() {
        when(jwtService.validateRefresh("invalidToken")).thenReturn(false);

        assertThatThrownBy(() -> authService.refresh("invalidToken"))
                .isInstanceOf(TokenException.class);
    }

    @Test
    @DisplayName("Refresh throws UserNotFoundException when user does not exist")
    void refreshThrowsUserNotFoundExceptionWhenUserDoesNotExist() {
        UUID userId = UUID.randomUUID();

        when(jwtService.validateRefresh("refreshToken")).thenReturn(true);
        when(jwtService.extractUserId("refreshToken")).thenReturn(userId.toString());
        when(credentialsRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("refreshToken"))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    @DisplayName("Validate returns true when token is valid")
    void validateReturnsTrueWhenTokenIsValid() {
        when(jwtService.validate("validToken")).thenReturn(true);

        assertThat(authService.validate("validToken")).isTrue();
    }

    @Test
    @DisplayName("Validate returns false when token is invalid")
    void validateReturnsFalseWhenTokenIsInvalid() {
        when(jwtService.validate("invalidToken")).thenReturn(false);

        assertThat(authService.validate("invalidToken")).isFalse();
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
