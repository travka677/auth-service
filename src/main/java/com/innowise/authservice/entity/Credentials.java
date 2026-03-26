package com.innowise.authservice.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Credentials extends Auditable {

    private UUID userId;
    private String email;
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    private Role role;
}
