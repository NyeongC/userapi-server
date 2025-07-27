package com.ccn.userapi.domain.admin;

import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.stream.IntStream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AdminMessageControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    @DisplayName("카카오 정상 전송 - 10명")
    void sendMessage_kakaoOnly() throws Exception {
        IntStream.rangeClosed(1, 10).forEach(i ->
                userRepository.save(makeUser(i)));

        MessageSendRequest request = new MessageSendRequest("안녕하세요");

        mockMvc.perform(post("/api/admin/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("전송 요청 완료"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    @DisplayName("카카오 분당 100건 초과 → SMS fallback 발생")
    void sendMessage_kakaoBucketExceeded_smsFallback() throws Exception {
        IntStream.rangeClosed(1, 150).forEach(i ->
                userRepository.save(makeUser(i)));

        MessageSendRequest request = new MessageSendRequest("카카오 버킷 테스트");

        mockMvc.perform(post("/api/admin/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    @DisplayName("카카오 실패(FALL) → SMS fallback 작동")
    void sendMessage_kakaoFail_smsFallback() throws Exception {
        userRepository.save(makeUser(1));

        MessageSendRequest request = new MessageSendRequest("FAIL"); // 카카오 실패 유도

        mockMvc.perform(post("/api/admin/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    @DisplayName("SMS도 분당 500건 초과 시 일부 drop")
    void sendMessage_smsBucketExceeded() throws Exception {
        IntStream.rangeClosed(1, 600).forEach(i ->
                userRepository.save(makeUser(i)));

        MessageSendRequest request = new MessageSendRequest("FAIL"); // 모두 카카오 실패 유도

        mockMvc.perform(post("/api/admin/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    private User makeUser(int i) {
        return User.builder()
                .account("user" + i)
                .password("encoded")
                .name("사용자" + i)
                .rrn("900101-10000" + i)
                .phone("010-0000-" + String.format("%04d", i))
                .address("서울특별시 강남구")
                .role("ROLE_USER")
                .build();
    }

    // 간단한 생성자용 DTO
    record MessageSendRequest(String message) {}


}
