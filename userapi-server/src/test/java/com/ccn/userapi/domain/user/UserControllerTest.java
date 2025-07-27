package com.ccn.userapi.domain.user;

import com.ccn.userapi.domain.user.dto.SignUpRequest;
import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("회원가입 성공")
    void signUp_success() throws Exception {
        SignUpRequest request = new SignUpRequestBuilder()
                .account("user1")
                .password("password123")
                .name("홍길동")
                .rrn("900101-1234567")
                .phone("010-1234-5678")
                .address("서울시 강남구")
                .build();

        mockMvc.perform(post("/api/user/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("계정 중복으로 회원가입 실패")
    void signUp_duplicateAccount() throws Exception {
        User existing = User.builder()
                .account("user1")
                .password(passwordEncoder.encode("pw"))
                .name("김철수")
                .rrn("800101-1111111")
                .phone("010-9999-8888")
                .address("서울시 종로구")
                .build();
        userRepository.save(existing);

        SignUpRequest request = new SignUpRequestBuilder()
                .account("user1") // 중복 계정
                .password("password123")
                .name("홍길동")
                .rrn("900101-1234567")
                .phone("010-1234-5678")
                .address("서울시 강남구")
                .build();

        mockMvc.perform(post("/api/user/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("주민등록번호 중복으로 회원가입 실패")
    void signUp_duplicateRrn() throws Exception {
        User existing = User.builder()
                .account("user2")
                .password(passwordEncoder.encode("pw"))
                .name("김철수")
                .rrn("900101-1234567") // 중복 주민번호
                .phone("010-9999-8888")
                .address("서울시 종로구")
                .build();
        userRepository.save(existing);

        SignUpRequest request = new SignUpRequestBuilder()
                .account("user3")
                .password("password123")
                .name("홍길동")
                .rrn("900101-1234567") // 중복
                .phone("010-1234-5678")
                .address("서울시 강남구")
                .build();

        mockMvc.perform(post("/api/user/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // 테스트용 빌더 내부 클래스
    private static class SignUpRequestBuilder {
        private final SignUpRequest request;

        public SignUpRequestBuilder() {
            this.request = new SignUpRequest();
        }

        public SignUpRequestBuilder account(String account) {
            setField("account", account); return this;
        }

        public SignUpRequestBuilder password(String password) {
            setField("password", password); return this;
        }

        public SignUpRequestBuilder name(String name) {
            setField("name", name); return this;
        }

        public SignUpRequestBuilder rrn(String rrn) {
            setField("rrn", rrn); return this;
        }

        public SignUpRequestBuilder phone(String phone) {
            setField("phone", phone); return this;
        }

        public SignUpRequestBuilder address(String address) {
            setField("address", address); return this;
        }

        public SignUpRequest build() {
            return request;
        }

        private void setField(String fieldName, String value) {
            try {
                var field = SignUpRequest.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(request, value);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
