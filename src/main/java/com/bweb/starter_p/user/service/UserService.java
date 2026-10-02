package com.bweb.starter_p.user.service;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.bweb.starter_p.user.dto.UpdateUserRequest;
import com.bweb.starter_p.user.dto.UserResponse;
import com.bweb.starter_p.user.entity.UserAccount;
import com.bweb.starter_p.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;

  @Transactional(readOnly = true)
  public UserResponse getCurrentUser(UUID userId) {
    return UserResponse.from(findUser(userId));
  }

  @Transactional
  public UserResponse updateCurrentUser(UUID userId, UpdateUserRequest request) {
    UserAccount user = findUser(userId);
    if (request.firstName() != null) {
      user.setFirstName(normalizeOptionalName(request.firstName()));
    }
    if (request.lastName() != null) {
      user.setLastName(normalizeOptionalName(request.lastName()));
    }
    return UserResponse.from(user);
  }

  private UserAccount findUser(UUID userId) {
    return userRepository.findById(userId)
        .filter(UserAccount::isActive)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
  }

  private String normalizeOptionalName(String name) {
    return name.isBlank() ? null : name.trim();
  }
}