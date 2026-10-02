package com.bweb.starter_p.auth.service;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.bweb.starter_p.auth.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenCleanupJob {

  private final RefreshTokenRepository refreshTokenRepository;

  @Scheduled(cron = "0 0 3 * * *")
  @Transactional
  public void deleteExpiredRefreshTokens() {
    int deletedCount = refreshTokenRepository.deleteByExpiresAtBefore(Instant.now());
    if (deletedCount > 0) {
      log.info("Deleted {} expired refresh tokens", deletedCount);
    }
  }
}
