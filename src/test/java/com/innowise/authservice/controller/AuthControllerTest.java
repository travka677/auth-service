package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.exception.AuthException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.UserNotFoundException;
import com.innowise.authservice.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(value = AuthController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @Test
    @DisplayName("Register returns 201 when request is valid")
    void registerReturns201WhenRequestIsValid() throws Exception {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        doNothing().when(authService).register(any(RegistrationRequest.class));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Register returns 400 when email is invalid")
    void registerReturns400WhenEmailIsInvalid() throws Exception {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("invalidEmail");
        request.setPassword("password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Register returns 400 when password is too short")
    void registerReturns400WhenPasswordIsTooShort() throws Exception {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@example.com");
        request.setPassword("123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Register returns 401 when email is already taken")
    void registerReturns401WhenEmailIsAlreadyTaken() throws Exception {
        RegistrationRequest request = new RegistrationRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        doThrow(new AuthException("User with email test@example.com already exists"))
                .when(authService).register(any(RegistrationRequest.class));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("User with email test@example.com already exists"));
    }

    @Test
    @DisplayName("Login returns tokens when credentials are valid")
    void loginReturnsTokensWhenCredentialsAreValid() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        AuthResponse response = new AuthResponse("accessToken", "refreshToken");

        when(authService.login(any(AuthRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.refreshToken").value("refreshToken"));
    }

    @Test
    @DisplayName("Login returns 404 when user does not exist")
    void loginReturns404WhenUserDoesNotExist() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("unknown@example.com");
        request.setPassword("password123");

        when(authService.login(any(AuthRequest.class)))
                .thenThrow(new UserNotFoundException("User not found with email: unknown@example.com"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found with email: unknown@example.com"));
    }

    @Test
    @DisplayName("Login returns 401 when password is invalid")
    void loginReturns401WhenPasswordIsInvalid() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrongPassword");

        when(authService.login(any(AuthRequest.class)))
                .thenThrow(new AuthException("Invalid password"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid password"));
    }

    @Test
    @DisplayName("Login returns 400 when email is blank")
    void loginReturns400WhenEmailIsBlank() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("");
        request.setPassword("password123");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Refresh returns new access token when refresh token is valid")
    void refreshReturnsNewAccessTokenWhenRefreshTokenIsValid() throws Exception {
        when(authService.refresh("validRefreshToken")).thenReturn("newAccessToken");

        mockMvc.perform(post("/auth/refresh")
                        .param("token", "validRefreshToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("newAccessToken"));
    }

    @Test
    @DisplayName("Refresh returns 401 when refresh token is invalid")
    void refreshReturns401WhenRefreshTokenIsInvalid() throws Exception {
        when(authService.refresh("invalidToken"))
                .thenThrow(new TokenException("Invalid refresh token"));

        mockMvc.perform(post("/auth/refresh")
                        .param("token", "invalidToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid refresh token"));
    }

    @Test
    @DisplayName("Validate returns true when token is valid")
    void validateReturnsTrueWhenTokenIsValid() throws Exception {
        when(authService.validate("validToken")).thenReturn(true);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "validToken"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }

    @Test
    @DisplayName("Validate returns false when token is invalid")
    void validateReturnsFalseWhenTokenIsInvalid() throws Exception {
        when(authService.validate("invalidToken")).thenReturn(false);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "invalidToken"))
                .andExpect(status().isOk())
                .andExpect(content().string("false"));
    }

    @Test
    @DisplayName("Assign admin returns 200 when user exists")
    void assignAdminReturns200WhenUserExists() throws Exception {
        UUID userId = UUID.randomUUID();

        doNothing().when(authService).assignAdminRole(userId);

        mockMvc.perform(patch("/auth/admin/assign/" + userId))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Assign admin returns 404 when user does not exist")
    void assignAdminReturns404WhenUserDoesNotExist() throws Exception {
        UUID userId = UUID.randomUUID();

        doThrow(new UserNotFoundException("User not found"))
                .when(authService).assignAdminRole(userId);

        mockMvc.perform(patch("/auth/admin/assign/" + userId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found"));
    }
}
