package com.bweb.starter_p;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
		"spring.datasource.url=jdbc:h2:mem:starter_p_context;MODE=MySQL;DB_CLOSE_DELAY=-1",
		"spring.datasource.username=sa",
		"spring.datasource.password=",
		"spring.datasource.driver-class-name=org.h2.Driver",
		"spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect",
		"spring.jpa.hibernate.ddl-auto=validate",
		"app.jwt.secret=test-secret-key-that-is-long-enough-for-hmac-sha256",
		"app.jwt.access-token-lifetime=15m",
		"app.jwt.refresh-token-lifetime=7d",
		"app.cors.allowed-origins=http://localhost:5173",
		"app.security.cookie-secure=false",
		"app.security.cookie-same-site=Lax"
})
class StarterPApplicationTests {

	@Test
	void contextLoads() {
	}

}
