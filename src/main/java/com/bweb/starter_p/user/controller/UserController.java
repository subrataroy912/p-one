package com.bweb.starter_p.user.controller;

import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bweb.starter_p.user.dto.UpdateUserRequest;
import com.bweb.starter_p.user.dto.UserResponse;
import com.bweb.starter_p.user.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/users")
@Validated
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @GetMapping("/me")
  public UserResponse getCurrentUser(Authentication authentication) {
    return userService.getCurrentUser(UUID.fromString(authentication.getName()));
  }

  @PatchMapping("/me")
  public UserResponse updateCurrentUser(
      Authentication authentication,
      @Valid @RequestBody UpdateUserRequest request) {
    return userService.updateCurrentUser(UUID.fromString(authentication.getName()), request);
  }
}