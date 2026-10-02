package com.bweb.starter_p;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class StarterPApplication {

	public static void main(String[] args) {
		SpringApplication.run(StarterPApplication.class, args);
	}

}
