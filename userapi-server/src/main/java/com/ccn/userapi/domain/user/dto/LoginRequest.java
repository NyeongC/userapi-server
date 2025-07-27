package com.ccn.userapi.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginRequest {

    @NotBlank
    private String account;

    @NotBlank
    private String password;
}
