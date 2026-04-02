package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.ValidateResponse;

import java.util.UUID;

public interface AuthService {

    void register(RegistrationRequest request);

    AuthResponse login(AuthRequest request);

    String refresh(String rawRefresh);

    void logout(String rawRefresh);

    ValidateResponse validate(String token);

    void assignAdminRole(UUID userId);
}
