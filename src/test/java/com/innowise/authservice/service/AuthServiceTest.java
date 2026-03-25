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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private CredentialsRepository repository;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    @DisplayName("Should successfully register user with default role")
    void shouldRegisterUserWithDefaultRole() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("dev@innowise.com");
        request.setPassword("password");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.empty());
        when(encoder.encode(anyString())).thenReturn("hashed_password");

        authService.register(request);

        verify(repository).save(argThat(c -> c.getRole() == Role.USER));
    }

    @Test
    @DisplayName("Should throw AuthException for existing email")
    void shouldThrowAuthExceptionForExistingEmail() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("taken@innowise.com");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.of(new Credentials()));

        assertThrows(AuthException.class, () -> authService.register(request));
    }

    @Test
    @DisplayName("Should fallback to USER role for invalid role input")
    void shouldFallbackToUserRoleForInvalidRoleInput() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@test.com");
        request.setRole("UNKNOWN_ROLE");

        when(repository.findByEmail(any())).thenReturn(Optional.empty());
        when(encoder.encode(any())).thenReturn("hash");

        authService.register(request);

        verify(repository).save(argThat(c -> c.getRole() == Role.USER));
    }

    @Test
    @DisplayName("Should return tokens for valid credentials")
    void shouldReturnTokensForValidCredentials() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@innowise.com");
        request.setPassword("correct_password");

        Credentials credentials = Credentials.builder()
                .id(UUID.randomUUID())
                .password("hashed_password")
                .build();

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(encoder.matches(request.getPassword(), credentials.getPassword())).thenReturn(true);
        when(jwtService.generateToken(credentials, false)).thenReturn("at");
        when(jwtService.generateToken(credentials, true)).thenReturn("rt");

        AuthResponse response = authService.login(request);

        assertAll(
                () -> assertEquals("at", response.getAccessToken()),
                () -> assertEquals("rt", response.getRefreshToken())
        );
    }

    @Test
    @DisplayName("Should throw AuthException for incorrect password")
    void shouldThrowAuthExceptionForIncorrectPassword() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@innowise.com");
        request.setPassword("wrong");

        Credentials credentials = new Credentials();
        credentials.setPassword("hashed");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(encoder.matches(eq(request.getPassword()), anyString())).thenReturn(false);

        assertThrows(AuthException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("Should throw UserNotFoundException for non-existent email")
    void shouldThrowUserNotFoundExceptionForNonExistentEmail() {
        AuthRequest request = new AuthRequest();
        request.setEmail("notfound@test.com");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("Should return new access token for valid refresh token")
    void shouldReturnNewAccessTokenForValidRefreshToken() {
        String rt = "valid-rt";
        UUID userId = UUID.randomUUID();
        Credentials credentials = new Credentials();

        when(jwtService.validate(rt)).thenReturn(true);
        when(jwtService.extractUserId(rt)).thenReturn(userId.toString());
        when(repository.findById(userId)).thenReturn(Optional.of(credentials));
        when(jwtService.generateToken(credentials, false)).thenReturn("new-at");

        String result = authService.refresh(rt);

        assertEquals("new-at", result);
    }

    @Test
    @DisplayName("Should throw TokenException for invalid refresh token")
    void shouldThrowTokenExceptionForInvalidRefreshToken() {
        String badToken = "bad-token";
        when(jwtService.validate(badToken)).thenReturn(false);

        assertThrows(TokenException.class, () -> authService.refresh(badToken));
    }

    @Test
    @DisplayName("Should return true for valid token validation")
    void shouldReturnTrueForValidTokenValidation() {
        String token = "token";
        when(jwtService.validate(token)).thenReturn(true);
        assertTrue(authService.validate(token));
    }
}
