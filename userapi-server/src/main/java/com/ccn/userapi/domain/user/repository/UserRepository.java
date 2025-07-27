package com.ccn.userapi.domain.user.repository;

import com.ccn.userapi.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByAccount(String account);
    boolean existsByRrn(String rrn);
    Optional<User> findByAccount(String account);
}
