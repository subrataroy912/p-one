package com.bweb.starter_p;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(properties = {
		"spring.datasource.url=jdbc:h2:mem:starter_p_schema;MODE=MySQL;DB_CLOSE_DELAY=-1",
		"spring.flyway.enabled=true",
		"spring.jpa.hibernate.ddl-auto=validate",
		"spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect"
})
@ActiveProfiles("test")
class StarterPApplicationTests {

	@Test
	void contextLoads() {
	}

}
