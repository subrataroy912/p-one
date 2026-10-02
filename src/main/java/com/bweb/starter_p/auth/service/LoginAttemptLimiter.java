package com.bweb.starter_p.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class LoginAttemptLimiter {

  private static final int MAX_FAILED_ATTEMPTS = 5;
  private static final Duration WINDOW = Duration.ofMinutes(15);
  private final Map<String, AttemptWindow> attempts = new HashMap<>();

  public synchronized void acquire(String remoteAddress, String email) {
    Instant now = Instant.now();
    String ipKey = ipKey(remoteAddress);
    String emailKey = emailKey(email);
    if (isLimited(ipKey, now) || isLimited(emailKey, now)) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many login attempts");
    }
    increment(ipKey, now);
    increment(emailKey, now);
  }

  @Scheduled(fixedDelay = 60000)
  public synchronized void removeExpiredWindows() {
    Instant now = Instant.now();
    Iterator<AttemptWindow> iterator = attempts.values().iterator();
    while (iterator.hasNext()) {
      if (!iterator.next().expiresAt().isAfter(now)) {
        iterator.remove();
      }
    }
  }

  private boolean isLimited(String key, Instant now) {
    AttemptWindow window = attempts.get(key);
    if (window == null) {
      return false;
    }
    if (!window.expiresAt().isAfter(now)) {
      attempts.remove(key);
      return false;
    }
    return window.count() >= MAX_FAILED_ATTEMPTS;
  }

  private void increment(String key, Instant now) {
    AttemptWindow window = attempts.get(key);
    if (window == null || !window.expiresAt().isAfter(now)) {
      attempts.put(key, new AttemptWindow(1, now.plus(WINDOW)));
    } else {
      attempts.put(key, new AttemptWindow(window.count() + 1, window.expiresAt()));
    }
  }

  private String ipKey(String remoteAddress) {
    return "ip:" + remoteAddress;
  }

  private String emailKey(String email) {
    return "email:" + email;
  }

  private record AttemptWindow(int count, Instant expiresAt) {
  }
}
