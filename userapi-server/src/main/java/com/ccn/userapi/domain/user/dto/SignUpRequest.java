package com.ccn.userapi.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class SignUpRequest {

    @NotBlank
    @Size(min = 4, max = 20)
    private String account;

    @NotBlank
    @Size(min = 6)
    private String password;

    @NotBlank
    private String name;

    @NotBlank
    private String rrn;

    @NotBlank
    private String phone;

    @NotBlank
    private String address;

    @NotBlank
    private String role;
}
