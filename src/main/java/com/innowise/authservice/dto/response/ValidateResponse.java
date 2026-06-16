package com.innowise.authservice.dto.response;

import com.innowise.authservice.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ValidateResponse {
    private final boolean valid;
    private final String userId;
    private final Role role;
}
