package com.ccn.userapi.domain.user.service;

import com.ccn.userapi.domain.user.dto.SignUpRequest;
import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(SignUpRequest request) {
        if (userRepository.existsByAccount(request.getAccount())) {
            throw new IllegalArgumentException("이미 존재하는 계정입니다.");
        }

        if (userRepository.existsByRrn(request.getRrn())) {
            throw new IllegalArgumentException("이미 등록된 주민등록번호입니다.");
        }

        User user = User.builder()
                .account(request.getAccount())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .rrn(request.getRrn())
                .phone(request.getPhone())
                .address(request.getAddress())
                .build();

        userRepository.save(user);
    }
}
