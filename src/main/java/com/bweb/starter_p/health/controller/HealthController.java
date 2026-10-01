package com.bweb.starter_p.health.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/health")
public class HealthController {

  @GetMapping("/alive")
  public Map<String, String> alive() {
    return Map.of("status", "alive");
  }
}