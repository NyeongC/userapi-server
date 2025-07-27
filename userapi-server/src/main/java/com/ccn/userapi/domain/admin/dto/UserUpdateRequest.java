package com.ccn.userapi.domain.admin.dto;

import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class UserUpdateRequest {

    @Size(min = 6, message = "비밀번호는 6자 이상이어야 합니다.")
    private String password;

    private String address;
}
