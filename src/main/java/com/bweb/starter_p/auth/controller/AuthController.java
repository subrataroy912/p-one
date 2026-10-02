package com.bweb.starter_p.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.CacheControl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

import com.bweb.starter_p.auth.dto.AuthResponse;
import com.bweb.starter_p.auth.dto.LoginRequest;
import com.bweb.starter_p.auth.dto.RegisterRequest;
import com.bweb.starter_p.auth.service.AuthCookieService;
import com.bweb.starter_p.auth.service.AuthResult;
import com.bweb.starter_p.auth.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/auth")
@Validated
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final AuthCookieService authCookieService;

  @GetMapping("/csrf")
  public ResponseEntity<Map<String, String>> csrf(CsrfToken csrfToken) {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .body(Map.of("token", csrfToken.getToken()));
  }

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(
      @Valid @RequestBody RegisterRequest request,
      HttpServletResponse response) {
    AuthResult result = authService.register(request);
    authCookieService.setAuthCookies(response, result);
    return ResponseEntity.status(HttpStatus.CREATED).body(result.response());
  }

  @PostMapping("/login")
  public AuthResponse login(
      @Valid @RequestBody LoginRequest request,
      HttpServletRequest servletRequest,
      HttpServletResponse response) {
    AuthResult result = authService.login(request, servletRequest.getRemoteAddr());
    authCookieService.setAuthCookies(response, result);
    return result.response();
  }

  @PostMapping("/refresh")
  public AuthResponse refresh(HttpServletRequest request, HttpServletResponse response) {
    AuthResult result = authService.refresh(authCookieService.refreshToken(request));
    authCookieService.setAuthCookies(response, result);
    return result.response();
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
    authService.logout(authCookieService.refreshToken(request));
    authCookieService.clearAuthCookies(response);
    return ResponseEntity.noContent().build();
  }
}