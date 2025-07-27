package com.ccn.message.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MessageController {

    @PostMapping("/kakaotalk-messages")
    public ResponseEntity<Void> sendKakaoMessage(@RequestBody(required = false) Map<String, String> body) {

        System.out.println("🔵 KakaoTalk API called");
        System.out.println("📦 Body: " + body);

        if (body == null || !body.containsKey("phone") || !body.containsKey("message")) {
            System.out.println("KAKAO - " + 400);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // 400
        }

        if ("FAIL".equalsIgnoreCase(body.get("message"))) {
            System.out.println("KAKAO - " + 500);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build(); // 500
        }

        return ResponseEntity.ok().build(); // 200
    }
}
