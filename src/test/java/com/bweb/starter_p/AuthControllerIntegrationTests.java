package com.bweb.starter_p;

import java.util.UUID;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTests {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @Test
        void aliveEndpointIsPublic() throws Exception {
                mockMvc.perform(get("/v1/health/alive"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.status").value("alive"));
        }

        @Test
        void registerRefreshLogoutAndAccessUserEndpoints() throws Exception {
                String email = "auth-" + UUID.randomUUID() + "@example.com";
                MvcResult csrfResponse = mockMvc.perform(get("/v1/auth/csrf"))
                                .andExpect(status().isOk())
                                .andReturn();
                String csrfToken = objectMapper.readTree(csrfResponse.getResponse().getContentAsString())
                                .get("token").asText();
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

                MvcResult refresh = mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(refreshCookie))
                                .andExpect(status().isOk())
                                .andReturn();
                Cookie rotatedRefreshCookie = refresh.getResponse().getCookie("refreshToken");
                Assertions.assertNotNull(rotatedRefreshCookie);

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(refreshCookie))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(withCsrf(post("/v1/auth/logout"), csrfCookie, csrfToken)
                                .cookie(rotatedRefreshCookie))
                                .andExpect(status().isNoContent());

                mockMvc.perform(withCsrf(post("/v1/auth/refresh"), csrfCookie, csrfToken)
                                .cookie(rotatedRefreshCookie))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(options("/v1/users/me")
                                .header("Origin", "http://localhost:5173")
                                .header("Access-Control-Request-Method", "PATCH")
                                .header("Access-Control-Request-Headers", "content-type,x-xsrf-token"))
                                .andExpect(status().isOk())
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                                                .string("Access-Control-Allow-Credentials", "true"));
        }

        private MockHttpServletRequestBuilder withCsrf(
                        MockHttpServletRequestBuilder request,
                        Cookie csrfCookie,
                        String csrfToken) {
                return request.cookie(csrfCookie).header("X-XSRF-TOKEN", csrfToken);
        }
}