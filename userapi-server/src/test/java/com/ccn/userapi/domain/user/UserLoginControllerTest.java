package com.ccn.userapi.domain.user;

import com.ccn.userapi.domain.user.dto.LoginRequest;
import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserLoginControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        User user = User.builder()
                .account("user1")
                .password(passwordEncoder.encode("pw1234"))
                .name("홍길동")
                .rrn("901010-1234567")
                .phone("010-1111-2222")
                .address("서울 강남구")
                .role("ROLE_USER")
                .build();

        userRepository.save(user);
    }

    @Test
    @DisplayName("로그인 성공")
    void login_success() throws Exception {
        LoginRequest request = new LoginRequestBuilder()
                .account("user1")
                .password("pw1234")
                .build();

        mockMvc.perform(post("/api/user/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("로그인 성공"));
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호 불일치")
    void login_fail_wrongPassword() throws Exception {
        LoginRequest request = new LoginRequestBuilder()
                .account("user1")
                .password("wrongpass")
                .build();

        mockMvc.perform(post("/api/user/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("로그인 후 세션에 인증정보 저장 확인")
    void login_session_contains_authentication() throws Exception {
        LoginRequest request = new LoginRequestBuilder()
                .account("user1")
                .password("pw1234")
                .build();

        MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/api/user/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn()
                .getRequest()
                .getSession(false);

        assertThat(session).isNotNull();
        SecurityContext context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        assertThat(context).isNotNull();
        assertThat(context.getAuthentication().getName()).isEqualTo("user1");
        assertThat(context.getAuthentication().getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER"))).isTrue();
    }

    // 테스트용 리플렉션 빌더
    private static class LoginRequestBuilder {
        private final LoginRequest req = new LoginRequest();

        public LoginRequestBuilder account(String account) {
            setField("account", account); return this;
        }

        public LoginRequestBuilder password(String password) {
            setField("password", password); return this;
        }

        public LoginRequest build() {
            return req;
        }

        private void setField(String field, Object value) {
            try {
                var f = LoginRequest.class.getDeclaredField(field);
                f.setAccessible(true);
                f.set(req, value);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
