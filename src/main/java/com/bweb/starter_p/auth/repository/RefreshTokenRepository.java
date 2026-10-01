package com.bweb.starter_p.auth.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.bweb.starter_p.auth.entity.RefreshToken;

import jakarta.persistence.LockModeType;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select token from RefreshToken token where token.tokenHash = :tokenHash and token.revokedAt is null")
  Optional<RefreshToken> findActiveForUpdate(@Param("tokenHash") String tokenHash);

  Optional<RefreshToken> findByTokenHashAndRevokedAtIsNull(String tokenHash);
}