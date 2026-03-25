package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthException;
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
    @DisplayName("Should successfully register a new user even if role is null")
    void registerNewUser() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("dev@innowise.com");
        request.setPassword("password");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.empty());
        when(encoder.encode(anyString())).thenReturn("hashed_password");

        authService.register(request);

        verify(repository).save(argThat(credentials -> credentials.getRole() == Role.USER));
    }

    @Test
    @DisplayName("Should throw AuthException when email is already taken")
    void registerDuplicateEmail() {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("taken@innowise.com");

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.of(new Credentials()));

        assertThrows(AuthException.class, () -> authService.register(request));
        verify(repository, never()).save(any(Credentials.class));
    }

    @Test
    @DisplayName("Should return AuthResponse for valid login credentials")
    void loginSuccess() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@innowise.com");
        request.setPassword("correct_password");

        Credentials credentials = Credentials.builder()
                .id(UUID.randomUUID())
                .email(request.getEmail())
                .password("hashed_password")
                .role(Role.USER)
                .build();

        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.of(credentials));
        when(encoder.matches(request.getPassword(), credentials.getPassword())).thenReturn(true);
        when(jwtService.generateToken(credentials, false)).thenReturn("access_token");
        when(jwtService.generateToken(credentials, true)).thenReturn("refresh_token");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("access_token", response.getAccessToken());
        assertEquals("refresh_token", response.getRefreshToken());
    }

    @Test
    @DisplayName("Should throw AuthException for incorrect password")
    void loginWrongPassword() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@innowise.com");
        request.setPassword("wrong_password");

        Credentials credentials = new Credentials();
        credentials.setPassword("hashed_password");

        when(repository.findByEmail(anyString())).thenReturn(Optional.of(credentials));
        when(encoder.matches(anyString(), anyString())).thenReturn(false);

        assertThrows(AuthException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when email doesn't exist")
    void loginUserNotFound() {
        AuthRequest request = new AuthRequest();
        request.setEmail("unknown@innowise.com");

        when(repository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.login(request));
    }
}
