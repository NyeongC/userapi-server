package com.ccn.userapi.domain.admin.controller;

import com.ccn.userapi.domain.admin.dto.MessageSendRequest;
import com.ccn.userapi.domain.admin.service.AdminMessageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminMessageController {

    private final AdminMessageService adminMessageService;

    @PostMapping("/send")
    public ResponseEntity<String> sendMessage(@RequestBody @Valid MessageSendRequest request) {
        adminMessageService.sendToAllUsers(request.getMessage());
        return ResponseEntity.ok("전송 요청 완료");
    }
}
