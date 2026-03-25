package com.innowise.authservice.service;

import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.exception.AuthException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.UserNotFoundException;
import com.innowise.authservice.repository.CredentialsRepository;
import com.innowise.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialsRepository repository;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;

    public void register(RegistrationRequest request) {
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            throw new AuthException("User with this email already exists");
        }

        Role role = determineRole(request.getRole());
        Credentials credentials = Credentials.builder()
                .email(request.getEmail())
                .password(encoder.encode(request.getPassword()))
                .role(role)
                .build();

        repository.save(credentials);
    }

    public AuthResponse login(AuthRequest request) {
        Credentials credentials = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + request.getEmail()));

        if (!encoder.matches(request.getPassword(), credentials.getPassword())) {
            throw new AuthException("Invalid password");
        }

        String access = jwtService.generateToken(credentials, false);
        String refresh = jwtService.generateToken(credentials, true);
        return new AuthResponse(access, refresh);
    }

    public String refresh(String refreshToken) {
        if (!jwtService.validate(refreshToken)) {
            throw new TokenException("Invalid refresh token");
        }
        String userId = jwtService.extractUserId(refreshToken);
        Credentials credentials = repository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return jwtService.generateToken(credentials, false);
    }

    public boolean validate(String token) {
        return jwtService.validate(token);
    }

    private Role determineRole(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            return Role.USER;
        }

        try {
            return Role.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            return Role.USER;
        }
    }
}
