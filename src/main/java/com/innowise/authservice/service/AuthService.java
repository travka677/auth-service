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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialsRepository credentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public void register(RegistrationRequest request) {
        if (credentialsRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new AuthException("User with email " + request.getEmail() + " already exists");
        }

        Credentials credentials = Credentials.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        credentialsRepository.save(credentials);
    }

    public AuthResponse login(AuthRequest request) {
        Credentials credentials = credentialsRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException(
                        "User not found with email: " + request.getEmail())
                );

        if (!passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())) {
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
        Credentials credentials = credentialsRepository.findByUserId(UUID.fromString(userId))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return jwtService.generateToken(credentials, false);
    }

    public boolean validate(String token) {
        return jwtService.validate(token);
    }

    @Transactional
    public void assignAdminRole(UUID userId) {
        Credentials credentials = credentialsRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        credentials.setRole(Role.ADMIN);
        credentialsRepository.save(credentials);
    }
}
