package com.ccn.userapi.domain.user;

import com.ccn.userapi.domain.user.dto.LoginRequest;
import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserProfileControllerTest {

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
                .address("서울특별시 강남구 역삼동")
                .role("ROLE_USER")
                .build();

        userRepository.save(user);
    }

    @Test
    @DisplayName("로그인 후 /me 요청 시 사용자 정보 조회 성공")
    void getMyProfile_success() throws Exception {
        // 1. 로그인 요청
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

        // 2. 세션으로 /me 요청
        mockMvc.perform(get("/api/user/me")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.account").value("user1"))
                .andExpect(jsonPath("$.name").value("홍길동"))
                .andExpect(jsonPath("$.phone").value("010-1111-2222"))
                .andExpect(jsonPath("$.region").value("서울특별시")); // 주소의 시/도만 잘라졌는지 확인
    }

    // 리플렉션 빌더
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
