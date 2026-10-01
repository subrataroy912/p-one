package com.bweb.starter_p.auth.dto;

import java.util.UUID;

import com.bweb.starter_p.user.dto.UserResponse;

public record AuthResponse(
    UUID userId,
    String email,
    UserResponse user) {
}