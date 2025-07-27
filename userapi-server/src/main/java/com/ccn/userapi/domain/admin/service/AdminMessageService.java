package com.ccn.userapi.domain.admin.service;

import com.ccn.userapi.domain.user.entity.User;
import com.ccn.userapi.domain.user.repository.UserRepository;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminMessageService {

    private final UserRepository userRepository;
    private final MessageClient messageClient;
    @Qualifier("kakaoBucket") private final Bucket kakaoBucket;
    @Qualifier("smsBucket") private final Bucket smsBucket;

    public void sendToAllUsers(String content) {
        List<User> users = userRepository.findAllByRole("ROLE_USER");

        for (User user : users) {
            String fullMessage = formatMessage(user.getName(), content);

            // 테스트 전용: FAIL 메시지 강제 전송
            if ("FAIL".equals(content)) {
                fullMessage = "FAIL";
            }

            boolean sent = false;

            if (kakaoBucket.tryConsume(1)) {
                sent = messageClient.sendKakao(user.getPhone(), fullMessage);
            }

            if (!sent && smsBucket.tryConsume(1)) {
                messageClient.sendSms(user.getPhone(), fullMessage);
            }

        }
    }

    private String formatMessage(String name, String content) {
        return String.format("%s님, 안녕하세요. 현대 오토에버입니다.\n%s", name, content);
    }
}
