package com.ccn.userapi.domain.admin;

import com.ccn.userapi.domain.admin.dto.UserUpdateRequest;
import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AdminUserControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
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

        IntStream.rangeClosed(1, 10).forEach(i -> {
            userRepository.save(User.builder()
                    .account("user" + i)
                    .password(passwordEncoder.encode("pw" + i))
                    .name("사용자" + i)
                    .rrn("900101-100000" + i)
                    .phone("010-0000-000" + i)
                    .address("서울 " + i + "번지")
                    .role("ROLE_USER")
                    .build());
        });
    }

    private String basicAuthHeader(String username, String password) {
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes());
    }

    @Test
    @DisplayName("회원 페이징 조회 성공")
    void getUsers_success() throws Exception {
        mockMvc.perform(get("/api/admin/users?page=0&size=5")
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, "1212")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(5))
                .andExpect(jsonPath("$.totalElements").value(11)); // admin + 10명
    }

    @Test
    @DisplayName("주소만 수정 성공")
    void updateAddress_only() throws Exception {
        User user = userRepository.findByAccount("user1").orElseThrow();

        UserUpdateRequest req = new UserUpdateRequest();
        setField(req, "address", "부산시 해운대구");

        mockMvc.perform(put("/api/admin/users/" + user.getId())
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk());

        User updated = userRepository.findById(user.getId()).orElseThrow();
        assertThat(updated.getAddress()).isEqualTo("부산시 해운대구");
        assertThat(passwordEncoder.matches("pw1", updated.getPassword())).isTrue();
    }

    @Test
    @DisplayName("비밀번호만 수정 성공")
    void updatePassword_only() throws Exception {
        User user = userRepository.findByAccount("user2").orElseThrow();

        UserUpdateRequest req = new UserUpdateRequest();
        setField(req, "password", "newSecret123");

        mockMvc.perform(put("/api/admin/users/" + user.getId())
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk());

        User updated = userRepository.findById(user.getId()).orElseThrow();
        assertThat(passwordEncoder.matches("newSecret123", updated.getPassword())).isTrue();
        assertThat(updated.getAddress()).isEqualTo(user.getAddress());
    }

    @Test
    @DisplayName("주소 + 비밀번호 동시 수정 성공")
    void updateBoth_success() throws Exception {
        User user = userRepository.findByAccount("user3").orElseThrow();

        UserUpdateRequest req = new UserUpdateRequest();
        setField(req, "password", "newPw456");
        setField(req, "address", "대구 수성구");

        mockMvc.perform(put("/api/admin/users/" + user.getId())
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk());

        User updated = userRepository.findById(user.getId()).orElseThrow();
        assertThat(updated.getAddress()).isEqualTo("대구 수성구");
        assertThat(passwordEncoder.matches("newPw456", updated.getPassword())).isTrue();
    }

    @Test
    @DisplayName("회원 삭제 성공")
    void deleteUser_success() throws Exception {
        User user = userRepository.findByAccount("user4").orElseThrow();

        mockMvc.perform(delete("/api/admin/users/" + user.getId())
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD)))
                .andExpect(status().isNoContent());

        assertThat(userRepository.existsById(user.getId())).isFalse();
    }

    @Test
    @DisplayName("존재하지 않는 사용자 수정 시도")
    void updateUser_notFound() throws Exception {
        UserUpdateRequest req = new UserUpdateRequest();
        setField(req, "address", "제주도");

        mockMvc.perform(put("/api/admin/users/99999")
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("존재하지 않는 사용자 삭제 시도")
    void deleteUser_notFound() throws Exception {
        mockMvc.perform(delete("/api/admin/users/99999")
                        .header("Authorization", basicAuthHeader(ADMIN_ACCOUNT, ADMIN_PASSWORD)))
                .andExpect(status().isBadRequest());
    }

    private void setField(Object target, String fieldName, Object value) {
        try {
            var field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }



}
