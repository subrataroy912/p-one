package com.bweb.starter_p.config;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SecurityConfigTests {

  @Test
  void rejectsSameSiteNoneWithoutSecureCookies() {
    SecurityConfig securityConfig = new SecurityConfig();

    assertThrows(IllegalStateException.class, () -> securityConfig.csrfTokenRepository(false, "None"));
  }
}
