package com.bweb.starter_p.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.bweb.starter_p.auth.service.JwtService;
import com.bweb.starter_p.security.JwtAuthenticationFilter;
import com.bweb.starter_p.user.repository.UserRepository;

import jakarta.servlet.DispatcherType;

@Configuration
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      CsrfTokenRepository csrfTokenRepository,
      CorsConfigurationSource corsConfigurationSource,
      JwtService jwtService,
      UserRepository userRepository) throws Exception {
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, userRepository);
    return http
        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
        .cors(cors -> cors.configurationSource(corsConfigurationSource))
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
            .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
            .requestMatchers(HttpMethod.GET, "/v1/auth/csrf").permitAll()
            .requestMatchers(HttpMethod.GET, "/v1/health/alive").permitAll()
            .requestMatchers("/v1/auth/register", "/v1/auth/login", "/v1/auth/refresh", "/v1/auth/logout").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(
                (request, response, exception) -> response.sendError(HttpStatus.UNAUTHORIZED.value())))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }

  @Bean
  CsrfTokenRepository csrfTokenRepository(
      @Value("${app.security.cookie-secure}") boolean secure,
      @Value("${app.security.cookie-same-site}") String sameSite) {
    if (!secure && "None".equalsIgnoreCase(sameSite)) {
      throw new IllegalStateException(
          "APP_COOKIE_SECURE must be true when APP_COOKIE_SAME_SITE=None");
    }
    CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    repository.setHeaderName("X-XSRF-TOKEN");
    repository.setCookieCustomizer(cookie -> cookie
        .secure(secure)
        .sameSite(sameSite)
        .path("/"));
    return repository;
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins}") String allowedOrigins) {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Arrays.stream(allowedOrigins.split(","))
        .map(String::trim)
        .filter(origin -> !origin.isEmpty())
        .toList());
    configuration.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  AuthenticationManager authenticationManager(
      UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder);
    return new ProviderManager(provider);
  }
}