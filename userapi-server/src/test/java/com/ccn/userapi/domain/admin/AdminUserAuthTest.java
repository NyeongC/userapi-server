package com.ccn.userapi.domain.admin;

import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AdminUserAuthTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private final String ADMIN_ACCOUNT = "admin";
    private final String ADMIN_PASSWORD = "1212";

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        User admin = User.builder()
                .account(ADMIN_ACCOUNT)
                .password(passwordEncoder.encode(ADMIN_PASSWORD))
                .name("관리자")
                .rrn("700101-1234567")
                .phone("010-9999-9999")
                .address("서울 본사")
                .role("ROLE_ADMIN")
                .build();

        userRepository.save(admin);

        User normalUser = User.builder()
                .account("user-auth-test")
                .password(passwordEncoder.encode("userpass"))
                .name("일반유저")
                .rrn("960101-1122334")
                .phone("010-3333-4444")
                .address("서울")
                .role("ROLE_USER")
                .build();

        userRepository.save(normalUser);
    }

    private String basicAuthHeader(String username, String password) {
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes());
    }

    @Test
    @DisplayName("인증 없이 접근 시 401 Unauthorized")
    void unauthorizedAccess() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("비밀번호 틀릴 경우 401 Unauthorized")
    void wrongPassword_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, "wrong-password")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("USER 권한으로 관리자 API 접근 시 403 Forbidden")
    void forbiddenAccessByUser() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", basicAuthHeader("user-auth-test", "userpass")))
                .andExpect(status().isForbidden());
    }
}
