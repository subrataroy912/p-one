package com.bweb.starter_p.auth.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.bweb.starter_p.auth.entity.RefreshToken;

import jakarta.persistence.LockModeType;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select token from RefreshToken token where token.tokenHash = :tokenHash")
  Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

  Optional<RefreshToken> findByTokenHashAndRevokedAtIsNull(String tokenHash);

  @Modifying
  @Query("update RefreshToken token set token.revokedAt = :revokedAt "
      + "where token.user.id = :userId and token.revokedAt is null")
  int revokeAllActiveForUser(@Param("userId") UUID userId, @Param("revokedAt") Instant revokedAt);

  @Modifying
  @Query("delete from RefreshToken token where token.expiresAt < :cutoff")
  int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}