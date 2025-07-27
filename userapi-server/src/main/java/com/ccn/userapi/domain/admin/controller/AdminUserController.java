package com.ccn.userapi.domain.admin.controller;

import com.ccn.userapi.domain.admin.dto.UserUpdateRequest;
import com.ccn.userapi.domain.admin.service.AdminUserService;
import com.ccn.userapi.domain.user.entity.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;

    @GetMapping
    public Page<User> getUsers(Pageable pageable) {
        return adminUserService.getUsers(pageable);
    }

    @PutMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public void updateUser(@PathVariable Long id, @RequestBody @Valid UserUpdateRequest request) {
        adminUserService.updateUser(id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUser(@PathVariable Long id) {
        adminUserService.deleteUser(id);
    }
}
