package com.ccn.message.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MessageController {

    @PostMapping(path = "/sms", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, String>> sendSms(@RequestParam(value = "phone", required = false) String phone,
                                                       @RequestParam Map<String, String> bodyParams) {
        System.out.println("SMS API called");
        System.out.println("Phone: " + phone);


        if (phone == null || !bodyParams.containsKey("message")) {
            System.out.println("SMS - " + 400);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // 400
        }

        if ("FAIL".equalsIgnoreCase(bodyParams.get("message"))) {
            System.out.println("SMS - " + 500);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build(); // 500
        }

        return ResponseEntity.ok(Map.of("result", "OK")); // 200
    }
}
