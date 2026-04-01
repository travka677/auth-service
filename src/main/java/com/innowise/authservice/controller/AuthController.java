package com.innowise.authservice.controller;

import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.RefreshResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Registers a new user
     *
     * @param request registration data (email, password)
     * @return HTTP 201 (Created) if registration is successful
     */
    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegistrationRequest request) {
        authService.register(request);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    /**
     * Authenticates a user
     *
     * @param request authentication data (email and password)
     * @return authentication response containing access and refresh tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Generates a new access token using a valid refresh token
     *
     * @param token refresh token
     * @return new access token wrapped in RefreshResponse
     */
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestParam String token) {
        return ResponseEntity.ok(new RefreshResponse(authService.refresh(token)));
    }

    /**
     * Validates a JWT token
     *
     * @param token JWT token
     * @return true if token is valid, false otherwise
     */
    @GetMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@RequestParam String token) {
        return ResponseEntity.ok(authService.validate(token));
    }

    /**
     * Assigns admin role to a user
     *
     * @param userId ID of the user to assign admin role
     * @return HTTP 200 (OK) if role is assigned successfully
     */
    @PatchMapping("/admin/assign/{userId}")
    public ResponseEntity<Void> assignAdmin(@PathVariable UUID userId) {
        authService.assignAdminRole(userId);
        return ResponseEntity.ok().build();
    }

    /**
     * Завершает сессию пользователя, отзывая refresh-токен
     *
     * @param token refresh-токен
     * @return HTTP 204 (No Content)
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestParam String token) {
        authService.logout(token);
        return ResponseEntity.noContent().build();
    }
}
