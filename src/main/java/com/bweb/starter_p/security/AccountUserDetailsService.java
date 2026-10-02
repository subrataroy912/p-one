package com.bweb.starter_p.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.bweb.starter_p.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    return userRepository.findByEmail(email.trim().toLowerCase(java.util.Locale.ROOT))
        .filter(com.bweb.starter_p.user.entity.UserAccount::isActive)
        .map(account -> User.withUsername(account.getEmail())
            .password(account.getPasswordHash())
            .authorities("ROLE_" + account.getRole().name())
            .build())
        .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));
  }
}