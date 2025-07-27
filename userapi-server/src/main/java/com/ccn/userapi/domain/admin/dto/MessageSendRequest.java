package com.ccn.userapi.domain.admin.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class MessageSendRequest {
    @NotBlank
    private String message;
}
