package com.bweb.starter_p.auth.service;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthCookieService {

  private static final String ACCESS_COOKIE = "accessToken";
  private static final String REFRESH_COOKIE = "refreshToken";
  private static final String ACCESS_COOKIE_PATH = "/";
  private static final String REFRESH_COOKIE_PATH = "/v1/auth";

  private final JwtService jwtService;

  @Value("${app.security.cookie-secure}")
  private boolean secure;

  @Value("${app.security.cookie-same-site}")
  private String sameSite;

  public void setAuthCookies(HttpServletResponse response, AuthResult result) {
    response.addHeader(HttpHeaders.SET_COOKIE,
        createCookie(ACCESS_COOKIE, result.accessToken(), ACCESS_COOKIE_PATH, jwtService.accessTokenLifetime()));
    response.addHeader(HttpHeaders.SET_COOKIE,
        createCookie(REFRESH_COOKIE, result.refreshToken(), REFRESH_COOKIE_PATH, jwtService.refreshTokenLifetime()));
  }

  public void clearAuthCookies(HttpServletResponse response) {
    response.addHeader(HttpHeaders.SET_COOKIE,
        createCookie(ACCESS_COOKIE, "", ACCESS_COOKIE_PATH, Duration.ZERO));
    response.addHeader(HttpHeaders.SET_COOKIE,
        createCookie(REFRESH_COOKIE, "", REFRESH_COOKIE_PATH, Duration.ZERO));
  }

  public String refreshToken(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (Cookie cookie : cookies) {
      if (REFRESH_COOKIE.equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }

  private String createCookie(String name, String value, String path, Duration maxAge) {
    return ResponseCookie.from(name, value)
        .httpOnly(true)
        .secure(secure)
        .sameSite(sameSite)
        .path(path)
        .maxAge(maxAge)
        .build()
        .toString();
  }
}