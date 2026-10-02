package com.bweb.starter_p;

import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Date;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import com.bweb.starter_p.auth.repository.RefreshTokenRepository;
import com.bweb.starter_p.auth.service.LoginAttemptLimiter;
import com.bweb.starter_p.auth.entity.RefreshToken;
import com.bweb.starter_p.user.repository.UserRepository;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.nullValue;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class AuthControllerIntegrationTests {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private RefreshTokenRepository refreshTokenRepository;

        @Autowired
        private LoginAttemptLimiter loginAttemptLimiter;

        @BeforeEach
        void resetLoginAttempts() {
                loginAttemptLimiter.reset();
        }

        @Test
        void aliveEndpointIsPublic() throws Exception {
                mockMvc.perform(get("/v1/health/alive"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.status").value("alive"));
        }

        @Test
        void invalidRegistrationReturnsBadRequest() throws Exception {
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();

                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"not-an-email\",\"password\":\"StrongPassword123\"}"))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Request validation failed"))
                                .andExpect(jsonPath("$.fields.email").exists());
        }

        @Test
        void duplicateRegistrationReturnsConflict() throws Exception {
                String email = "duplicate-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                String body = "{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email);

                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isCreated());
                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isConflict())
                                .andExpect(jsonPath("$.error").value("Email is already registered"));
        }

        @Test
        void loginIsRateLimitedByIpAndEmail() throws Exception {
                String email = "rate-limit-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                String clientIp = "192.0.2." + (10 + Math.abs(email.hashCode() % 200));

                for (int attempt = 0; attempt < 5; attempt++) {
                        mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                        .with(request -> {
                                                request.setRemoteAddr(clientIp);
                                                return request;
                                        })
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}".formatted(email)))
                                        .andExpect(status().isUnauthorized());
                }

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .with(request -> {
                                        request.setRemoteAddr(clientIp);
                                        return request;
                                })
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}".formatted(email)))
                                .andExpect(status().isTooManyRequests())
                                .andExpect(jsonPath("$.error").value("Too many login attempts"));

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .with(request -> {
                                        request.setRemoteAddr("192.0.2.250");
                                        return request;
                                })
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}".formatted(email)))
                                .andExpect(status().isTooManyRequests());

                String otherEmail = "same-ip-" + UUID.randomUUID() + "@example.com";
                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}"
                                                .formatted(otherEmail)))
                                .andExpect(status().isCreated());
                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .with(request -> {
                                        request.setRemoteAddr(clientIp);
                                        return request;
                                })
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}"
                                                .formatted(otherEmail)))
                                .andExpect(status().isOk());
        }

        @Test
        void successfulLoginClearsEmailFailures() throws Exception {
                String email = "clear-limit-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isCreated());

                for (int attempt = 0; attempt < 4; attempt++) {
                        mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}"
                                                        .formatted(email)))
                                        .andExpect(status().isUnauthorized());
                }
                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isOk());
                for (int attempt = 0; attempt < 4; attempt++) {
                        mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}"
                                                        .formatted(email)))
                                        .andExpect(status().isUnauthorized());
                }
                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"WrongPassword123\"}".formatted(email)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void passwordsOverBcryptByteLimitReturnBadRequest() throws Exception {
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                String tooManyUtf8Bytes = "অ".repeat(25) + "Abc123";

                mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"long-password@example.com\",\"password\":\"%s\"}"
                                                .formatted(tooManyUtf8Bytes)))
                                .andExpect(status().isBadRequest());
                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"long-password@example.com\",\"password\":\"%s\"}"
                                                .formatted(tooManyUtf8Bytes)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void expiredRefreshTokenReturnsUnauthorized() throws Exception {
                String expiredToken = Jwts.builder()
                                .subject(UUID.randomUUID().toString())
                                .claim("token_type", "refresh")
                                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                                .expiration(Date.from(Instant.now().minusSeconds(60)))
                                .signWith(Keys.hmacShaKeyFor(
                                                "test-secret-key-that-is-long-enough-for-hmac-sha256"
                                                                .getBytes(StandardCharsets.UTF_8)))
                                .compact();
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(new Cookie("refreshToken", expiredToken)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void unknownRouteWithValidAuthenticationRemainsNotFound() throws Exception {
                String email = "missing-route-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                MvcResult registration = mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isCreated())
                                .andReturn();

                mockMvc.perform(get("/v1/does-not-exist")
                                .cookie(registration.getResponse().getCookie("accessToken")))
                                .andExpect(status().isNotFound())
                                .andExpect(jsonPath("$.error").value("Resource not found"))
                                .andExpect(jsonPath("$.fields").isEmpty());
        }

        @Test
        void malformedJsonAndUnsupportedMethodUseApiErrorShape() throws Exception {
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{not-json"))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Malformed or unreadable request body"))
                                .andExpect(jsonPath("$.fields").isEmpty());

                mockMvc.perform(get("/v1/auth/register"))
                                .andExpect(status().isMethodNotAllowed())
                                .andExpect(jsonPath("$.error").value("HTTP method not allowed"))
                                .andExpect(jsonPath("$.fields").isEmpty());
        }

        @Test
        void staleRefreshReplayRevokesAllActiveSessions() throws Exception {
                String email = "stale-replay-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                MvcResult registration = mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isCreated())
                                .andReturn();
                String originalRefreshToken = registration.getResponse().getCookie("refreshToken").getValue();
                var user = userRepository.findByEmail(email).orElseThrow();
                RefreshToken originalStoredToken = refreshTokenRepository
                                .findByTokenHash(hashToken(originalRefreshToken)).orElseThrow();
                originalStoredToken.setRevokedAt(Instant.now().minusSeconds(60));
                refreshTokenRepository.save(originalStoredToken);

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isOk());
                Assertions.assertEquals(1, refreshTokenRepository.countByUser_IdAndRevokedAtIsNull(user.getId()));

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(new Cookie("refreshToken", originalRefreshToken)))
                                .andExpect(status().isUnauthorized());

                Assertions.assertEquals(0, refreshTokenRepository.countByUser_IdAndRevokedAtIsNull(user.getId()));
        }

        @Test
        void registerRefreshLogoutAndAccessUserEndpoints() throws Exception {
                String email = "auth-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                Assertions.assertNotNull(csrfCookie);

                String registrationBody = """
                                {"email":"%s","password":"StrongPassword123","firstName":"Test"}
                                """.formatted(email);
                mockMvc.perform(post("/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(registrationBody))
                                .andExpect(status().isForbidden());

                MvcResult registration = mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(registrationBody))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.accessToken").doesNotExist())
                                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                                .andReturn();
                Cookie accessCookie = registration.getResponse().getCookie("accessToken");
                Cookie refreshCookie = registration.getResponse().getCookie("refreshToken");
                Assertions.assertNotNull(accessCookie);
                Assertions.assertNotNull(refreshCookie);
                Assertions.assertTrue(accessCookie.isHttpOnly());
                Assertions.assertTrue(refreshCookie.isHttpOnly());

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.email").value(email));

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"wrong-password\"}".formatted(email)))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(get("/v1/users/me")
                                .cookie(accessCookie))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.email").value(email));

                mockMvc.perform(withCsrf(patch("/v1/users/me"), csrfCookie, csrfToken)
                                .cookie(accessCookie)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"lastName\":\"User\"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.firstName").value("Test"))
                                .andExpect(jsonPath("$.lastName").value("User"));

                mockMvc.perform(withCsrf(patch("/v1/users/me"), csrfCookie, csrfToken)
                                .cookie(accessCookie)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"firstName\":\"   \"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.firstName").value(nullValue()));

                MvcResult refresh = mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(refreshCookie))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie rotatedRefreshCookie = refresh.getResponse().getCookie("refreshToken");
                Assertions.assertNotNull(rotatedRefreshCookie);

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(refreshCookie))
                                .andExpect(status().isUnauthorized());

                MvcResult refreshAfterReplay = mockMvc.perform(
                                withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                                .cookie(rotatedRefreshCookie))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie newestRefreshCookie = refreshAfterReplay.getResponse().getCookie("refreshToken");

                mockMvc.perform(withCsrf(post("/v1/auth/logout"), csrfCookie, csrfToken)
                                .cookie(newestRefreshCookie))
                                .andExpect(status().isNoContent());

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(newestRefreshCookie))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(options("/v1/users/me")
                                .header("Origin", "http://localhost:5173")
                                .header("Access-Control-Request-Method", "PATCH")
                                .header("Access-Control-Request-Headers", "content-type,x-xsrf-token"))
                                .andExpect(status().isOk())
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                                                .string("Access-Control-Allow-Credentials", "true"))
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                                                .string("Access-Control-Max-Age", "3600"));
        }

        @Test
        void inactiveUserCannotLogin() throws Exception {
                String email = "inactive-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie csrfCookie = csrfResponse.getResponse().getCookie("XSRF-TOKEN");
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").stringValue();
                MvcResult registration = mockMvc.perform(withCsrf(post("/v1/auth/register"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isCreated())
                                .andReturn();
                var user = userRepository.findByEmail(email).orElseThrow();
                user.setActive(false);
                userRepository.save(user);

                mockMvc.perform(withCsrf(post("/v1/auth/login"), csrfCookie, csrfToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"%s\",\"password\":\"StrongPassword123\"}".formatted(email)))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(get("/v1/users/me")
                                .cookie(registration.getResponse().getCookie("accessToken")))
                                .andExpect(status().isUnauthorized());
                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(registration.getResponse().getCookie("refreshToken")))
                                .andExpect(status().isUnauthorized());
        }

        private MockHttpServletRequestBuilder withCsrf(
                        MockHttpServletRequestBuilder request,
                        Cookie csrfCookie,
                        String csrfToken) {
                return request.cookie(csrfCookie).header("X-XSRF-TOKEN", csrfToken);
        }

        private String hashToken(String token) throws Exception {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                                .digest(token.getBytes(StandardCharsets.UTF_8)));
        }
}
