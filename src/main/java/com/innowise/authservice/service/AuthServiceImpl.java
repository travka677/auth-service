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
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final CredentialsRepository credentialsRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${jwt.refresh-expiration}")
    private long refreshExp;

    @Override
    public void register(RegistrationRequest request) {
        if (credentialsRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new AuthException("User with email " + request.getEmail() + " already exists");
        }

        // TODO: call user-service to create user and get userId
        UUID userId = UUID.randomUUID();
        Credentials credentials = Credentials.builder()
                .userId(userId)
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        credentialsRepository.save(credentials);
    }

    @Override
    @Transactional
    public AuthResponse login(AuthRequest request) {
        Credentials credentials = credentialsRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException(
                        "User not found with email: " + request.getEmail()));

        if (!passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())) {
            throw new AuthException("Invalid password");
        }

        refreshTokenRepository.revokeAllByCredentials(credentials);

        String access = jwtService.generateToken(credentials, false);
        String rawRefresh = jwtService.generateToken(credentials, true);

        refreshTokenRepository.save(RefreshToken.builder()
                .token(rawRefresh)
                .credentials(credentials)
                .expiresAt(Instant.now().plusMillis(refreshExp))
                .revoked(false)
                .build());

        return new AuthResponse(access, rawRefresh);
    }

    @Override
    @Transactional
    public String refresh(String rawRefresh) {
        if (!jwtService.validateRefresh(rawRefresh)) {
            throw new TokenException("Invalid refresh token");
        }

        RefreshToken stored = refreshTokenRepository.findByToken(rawRefresh)
                .orElseThrow(() -> new TokenException("Refresh token not found"));

        if (stored.isRevoked()) {
            throw new TokenException("Refresh token has been revoked");
        }
        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new TokenException("Refresh token has expired");
        }

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        Credentials credentials = stored.getCredentials();
        String newRefresh = jwtService.generateToken(credentials, true);

        refreshTokenRepository.save(RefreshToken.builder()
                .token(newRefresh)
                .credentials(credentials)
                .expiresAt(Instant.now().plusMillis(refreshExp))
                .revoked(false)
                .build());

        return jwtService.generateToken(credentials, false);
    }

    @Override
    @Transactional
    public void logout(String rawRefresh) {
        RefreshToken stored = refreshTokenRepository.findByToken(rawRefresh)
                .orElseThrow(() -> new TokenException("Refresh token not found"));
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
    }

    @Override
    public ValidateResponse validate(String token) {
        return jwtService.validateAndExtract(token);
    }

    @Override
    @Transactional
    public void assignAdminRole(UUID userId) {
        Credentials credentials = credentialsRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        credentials.setRole(Role.ADMIN);
        credentialsRepository.save(credentials);
    }
}
