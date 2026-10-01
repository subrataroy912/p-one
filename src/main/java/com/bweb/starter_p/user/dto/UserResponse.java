package com.bweb.starter_p.user.dto;

import java.time.Instant;
import java.util.UUID;

import com.bweb.starter_p.user.entity.AccountRole;
import com.bweb.starter_p.user.entity.UserAccount;

public record UserResponse(
    UUID id,
    String email,
    String firstName,
    String lastName,
    AccountRole role,
    Instant createdAt) {

  public static UserResponse from(UserAccount user) {
    return new UserResponse(
        user.getId(),
        user.getEmail(),
        user.getFirstName(),
        user.getLastName(),
        user.getRole(),
        user.getCreatedAt());
  }
}