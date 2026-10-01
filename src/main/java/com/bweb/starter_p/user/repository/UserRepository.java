package com.bweb.starter_p.user.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bweb.starter_p.user.entity.UserAccount;

public interface UserRepository extends JpaRepository<UserAccount, UUID> {

  Optional<UserAccount> findByEmailIgnoreCase(String email);

  boolean existsByEmailIgnoreCase(String email);
}