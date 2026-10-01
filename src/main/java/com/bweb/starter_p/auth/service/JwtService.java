package com.bweb.starter_p.auth.service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

  private static final String TOKEN_TYPE_CLAIM = "token_type";
  private final SecretKey signingKey;
  private final Duration accessTokenLifetime;
  private final Duration refreshTokenLifetime;

  public JwtService(
      @Value("${app.jwt.secret}") String secret,
      @Value("${app.jwt.access-token-lifetime}") Duration accessTokenLifetime,
      @Value("${app.jwt.refresh-token-lifetime}") Duration refreshTokenLifetime) {
    byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
    if (secretBytes.length < 32) {
      throw new IllegalArgumentException("JWT_SECRET must be at least 32 bytes");
    }
    this.signingKey = Keys.hmacShaKeyFor(secretBytes);
    this.accessTokenLifetime = accessTokenLifetime;
    this.refreshTokenLifetime = refreshTokenLifetime;
  }

  public String createAccessToken(UUID userId) {
    return createToken(userId, "access", accessTokenLifetime);
  }

  public String createRefreshToken(UUID userId) {
    return createToken(userId, "refresh", refreshTokenLifetime);
  }

  public Instant refreshTokenExpiresAt() {
    return Instant.now().plus(refreshTokenLifetime);
  }

  public Duration accessTokenLifetime() {
    return accessTokenLifetime;
  }

  public Duration refreshTokenLifetime() {
    return refreshTokenLifetime;
  }

  public Claims parseAndValidate(String token, String expectedType) {
    Claims claims = Jwts.parser()
        .verifyWith(signingKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
    if (!expectedType.equals(claims.get(TOKEN_TYPE_CLAIM, String.class))) {
      throw new JwtException("Unexpected token type");
    }
    return claims;
  }

  private String createToken(UUID userId, String tokenType, Duration lifetime) {
    Instant issuedAt = Instant.now();
    return Jwts.builder()
        .id(UUID.randomUUID().toString())
        .subject(userId.toString())
        .claim(TOKEN_TYPE_CLAIM, tokenType)
        .issuedAt(Date.from(issuedAt))
        .expiration(Date.from(issuedAt.plus(lifetime)))
        .signWith(signingKey)
        .compact();
  }
}