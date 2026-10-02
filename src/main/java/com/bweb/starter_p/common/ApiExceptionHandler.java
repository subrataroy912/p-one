package com.bweb.starter_p.common;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ApiError> handleAuthenticationException(AuthenticationException exception) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(new ApiError("Authentication failed", Map.of()));
  }

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ApiError> handleResponseStatusException(ResponseStatusException exception) {
    HttpStatusCode status = exception.getStatusCode();
    String message = exception.getReason() == null ? status.toString() : exception.getReason();
    return ResponseEntity.status(status).body(new ApiError(message, Map.of()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiError> handleMethodArgumentNotValid(MethodArgumentNotValidException exception) {
    Map<String, String> fields = new LinkedHashMap<>();
    exception.getBindingResult().getFieldErrors()
        .forEach(error -> fields.putIfAbsent(error.getField(), error.getDefaultMessage()));
    return ResponseEntity.badRequest().body(new ApiError("Request validation failed", fields));
  }

  public record ApiError(String error, Map<String, String> fields) {
  }
}