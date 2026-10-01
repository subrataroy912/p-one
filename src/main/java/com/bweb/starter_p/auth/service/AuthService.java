package com.bweb.starter_p.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.bweb.starter_p.auth.dto.AuthResponse;
import com.bweb.starter_p.auth.dto.LoginRequest;
import com.bweb.starter_p.auth.dto.RegisterRequest;
import com.bweb.starter_p.auth.entity.RefreshToken;
import com.bweb.starter_p.auth.repository.RefreshTokenRepository;
import com.bweb.starter_p.user.dto.UserResponse;
import com.bweb.starter_p.user.entity.UserAccount;
import com.bweb.starter_p.user.repository.UserRepository;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final AuthenticationManager authenticationManager;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  @Transactional
  public AuthResult register(RegisterRequest request) {
    String email = normalizeEmail(request.email());
    if (userRepository.existsByEmailIgnoreCase(email)) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
    }

    UserAccount user = new UserAccount();
    user.setEmail(email);
    user.setFirstName(normalizeOptionalName(request.firstName()));
    user.setLastName(normalizeOptionalName(request.lastName()));
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    try {
      userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException exception) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
    }
    return issueTokens(user);
  }

  @Transactional
  public AuthResult login(LoginRequest request) {
    String email = normalizeEmail(request.email());
    try {
      authenticationManager.authenticate(
          UsernamePasswordAuthenticationToken.unauthenticated(email, request.password()));
    } catch (AuthenticationException exception) {
      throw new BadCredentialsException("Invalid email or password");
    }
    UserAccount user = userRepository.findByEmailIgnoreCase(email)
        .filter(UserAccount::isActive)
        .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
    return issueTokens(user);
  }

  @Transactional
  public AuthResult refresh(String rawRefreshToken) {
    String userId;
    try {
      userId = jwtService.parseAndValidate(rawRefreshToken, "refresh").getSubject();
    } catch (JwtException | IllegalArgumentException exception) {
      throw new BadCredentialsException("Invalid refresh token");
    }

    UUID parsedUserId;
    try {
      parsedUserId = UUID.fromString(userId);
    } catch (IllegalArgumentException exception) {
      throw new BadCredentialsException("Invalid refresh token");
    }

    String tokenHash = hashToken(rawRefreshToken);
    RefreshToken storedToken = refreshTokenRepository.findActiveForUpdate(tokenHash)
        .filter(token -> token.getExpiresAt().isAfter(Instant.now()))
        .filter(token -> token.getUser().getId().equals(parsedUserId))
        .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
    UserAccount user = storedToken.getUser();
    if (!user.isActive()) {
      throw new BadCredentialsException("Invalid refresh token");
    }

    storedToken.setRevokedAt(Instant.now());
    return issueTokens(user);
  }

  @Transactional
  public void logout(String rawRefreshToken) {
    if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
      return;
    }
    refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hashToken(rawRefreshToken))
        .ifPresent(token -> token.setRevokedAt(Instant.now()));
  }

  private AuthResult issueTokens(UserAccount user) {
    String refreshTokenValue = jwtService.createRefreshToken(user.getId());
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setTokenHash(hashToken(refreshTokenValue));
    refreshToken.setUser(user);
    refreshToken.setExpiresAt(jwtService.refreshTokenExpiresAt());
    refreshTokenRepository.save(refreshToken);

    UserResponse userResponse = UserResponse.from(user);
    String accessTokenValue = jwtService.createAccessToken(user.getId());
    AuthResponse response = new AuthResponse(user.getId(), user.getEmail(), userResponse);
    return new AuthResult(response, accessTokenValue, refreshTokenValue);
  }

  private String hashToken(String token) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private String normalizeEmail(String email) {
    return email.trim().toLowerCase(java.util.Locale.ROOT);
  }

  private String normalizeOptionalName(String name) {
    return name == null || name.isBlank() ? null : name.trim();
  }
}