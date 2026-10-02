package com.bweb.starter_p.security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bweb.starter_p.auth.service.JwtService;
import com.bweb.starter_p.user.entity.UserAccount;
import com.bweb.starter_p.user.repository.UserRepository;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserRepository userRepository;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String accessToken = cookieValue(request, "accessToken");
    if (accessToken != null) {
      authenticate(accessToken);
    }
    filterChain.doFilter(request, response);
  }

  private String cookieValue(HttpServletRequest request, String name) {
    jakarta.servlet.http.Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (jakarta.servlet.http.Cookie cookie : cookies) {
      if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
        return cookie.getValue();
      }
    }
    return null;
  }

  private void authenticate(String token) {
    if (SecurityContextHolder.getContext().getAuthentication() != null) {
      return;
    }
    try {
      UUID userId = UUID.fromString(jwtService.parseAndValidate(token, "access").getSubject());
      UserAccount user = userRepository.findById(userId)
          .filter(UserAccount::isActive)
          .orElseThrow(() -> new IllegalArgumentException("Inactive user"));
      var authentication = new UsernamePasswordAuthenticationToken(
          userId.toString(),
          null,
          List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())));
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (JwtException | IllegalArgumentException exception) {
      SecurityContextHolder.clearContext();
    }
  }
}