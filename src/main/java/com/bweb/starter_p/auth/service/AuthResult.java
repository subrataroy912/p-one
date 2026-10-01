package com.bweb.starter_p.auth.service;

import com.bweb.starter_p.auth.dto.AuthResponse;

public record AuthResult(AuthResponse response, String accessToken, String refreshToken) {
}