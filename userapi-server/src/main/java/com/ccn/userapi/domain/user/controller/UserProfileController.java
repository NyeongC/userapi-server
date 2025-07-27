package com.ccn.userapi.domain.user.controller;

import com.ccn.userapi.domain.user.dto.UserProfileResponse;
import com.ccn.userapi.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserProfileController {

    @GetMapping("/me")
    public UserProfileResponse getMyProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        String region = extractRegion(user.getAddress());

        return UserProfileResponse.builder()
                .account(user.getAccount())
                .name(user.getName())
                .phone(user.getPhone())
                .region(region)
                .build();
    }

    private String extractRegion(String address) {
        if (address == null || address.isBlank()) return "";
        return address.split(" ")[0]; // "서울특별시 강남구 역삼동" → "서울특별시"
    }
}
