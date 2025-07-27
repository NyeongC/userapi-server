package com.ccn.userapi.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class MessageServerCallTest {

    private final RestTemplate restTemplate = new RestTemplate();

    private String kakaoAuth() {
        return "Basic " + Base64.getEncoder().encodeToString("autoever:1234".getBytes());
    }

    private String smsAuth() {
        return "Basic " + Base64.getEncoder().encodeToString("autoever:5678".getBytes());
    }

    @Test
    @DisplayName("카카오톡 - 정상 200")
    void callKakao_200() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", kakaoAuth());

        Map<String, String> body = Map.of("phone", "010-1234-5678", "message", "안녕하세요");

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Void> response = restTemplate.postForEntity("http://localhost:8081/kakaotalk-messages", request, Void.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("카카오톡 - 요청 바디 누락 400")
    void callKakao_400() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", kakaoAuth());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            restTemplate.exchange("http://localhost:8081/kakaotalk-messages", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    @DisplayName("카카오톡 - 인증 실패 401")
    void callKakao_401() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Basic wrongAuth");

        Map<String, String> body = Map.of("phone", "010-1234-5678", "message", "안녕하세요");
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        try {
            restTemplate.exchange("http://localhost:8081/kakaotalk-messages", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다"); // 예외 없으면 테스트 실패
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    @DisplayName("카카오톡 - FAIL 메시지로 500")
    void callKakao_500() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", kakaoAuth());

        Map<String, String> body = Map.of("phone", "010-1234-5678", "message", "FAIL");
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        try {
            restTemplate.exchange("http://localhost:8081/kakaotalk-messages", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다");
        } catch (HttpServerErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    @DisplayName("SMS - 정상 200")
    void callSms_200() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", smsAuth());

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("message", "정상");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity("http://localhost:8082/sms?phone=010-8888-7777", request, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("result")).isEqualTo("OK");
    }

    @Test
    @DisplayName("SMS - 인증 실패 401")
    void callSms_401() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic wrongAuth");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("message", "문자");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            restTemplate.exchange("http://localhost:8082/sms?phone=010-8888-7777", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    @DisplayName("SMS - 요청 바디 누락 400")
    void callSms_400() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", smsAuth());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            restTemplate.exchange("http://localhost:8082/sms?phone=010-8888-7777", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    @DisplayName("SMS - FAIL 메시지로 500")
    void callSms_500() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", smsAuth());

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("message", "FAIL");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            restTemplate.exchange("http://localhost:8082/sms?phone=010-8888-7777", HttpMethod.POST, request, Void.class);
            fail("예외가 발생해야 합니다");
        } catch (HttpServerErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
