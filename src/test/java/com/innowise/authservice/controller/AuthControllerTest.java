package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.dto.request.AuthRequest;
import com.innowise.authservice.dto.request.RegistrationRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.UserNotFoundException;
import com.innowise.authservice.filter.JwtAuthenticationFilter;
import com.innowise.authservice.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
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

    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() throws Exception {
        doAnswer(invocation -> {
            HttpServletRequest request = invocation.getArgument(0);
            HttpServletResponse response = invocation.getArgument(1);
            FilterChain chain = invocation.getArgument(2);
            chain.doFilter(request, response);
            return null;
        }).when(jwtAuthenticationFilter).doFilter(any(), any(), any());
    }

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
    @DisplayName("Validate returns structured response when token is valid")
    void validateReturnsStructuredResponseWhenTokenIsValid() throws Exception {
        UUID userId = UUID.randomUUID();
        ValidateResponse response = new ValidateResponse(true, userId.toString(), Role.USER);

        when(authService.validate("validToken")).thenReturn(response);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "validToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(userId.toString()))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("Validate returns valid=false when token is invalid")
    void validateReturnsInvalidResponseWhenTokenIsInvalid() throws Exception {
        ValidateResponse response = new ValidateResponse(false, null, null);

        when(authService.validate("invalidToken")).thenReturn(response);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "invalidToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.userId").isEmpty())
                .andExpect(jsonPath("$.role").isEmpty());
    }

    @Test
    @DisplayName("Logout returns 204 when refresh token is valid")
    void logoutReturns204WhenRefreshTokenIsValid() throws Exception {
        doNothing().when(authService).logout("validRefreshToken");

        mockMvc.perform(post("/auth/logout")
                        .param("token", "validRefreshToken"))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Logout returns 401 when refresh token is not found")
    void logoutReturns401WhenRefreshTokenIsNotFound() throws Exception {
        doThrow(new TokenException("Refresh token not found"))
                .when(authService).logout("unknownToken");

        mockMvc.perform(post("/auth/logout")
                        .param("token", "unknownToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token not found"));
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
