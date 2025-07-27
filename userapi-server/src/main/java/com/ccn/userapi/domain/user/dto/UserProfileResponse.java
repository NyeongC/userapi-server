package com.ccn.userapi.domain.user.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponse {
    private String account;
    private String name;
    private String phone;
    private String region; // 주소 시/도만 반환
}
