package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.domain.Role;
import com.github.h3yow.revocablesessionauthjava.domain.User;
import com.github.h3yow.revocablesessionauthjava.security.AuthService;
import com.github.h3yow.revocablesessionauthjava.web.dto.RoleChangeRequest;
import com.github.h3yow.revocablesessionauthjava.web.dto.UserView;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 管理接口：变更用户角色。变更立即生效，影响该用户所有已签发访问令牌的后续判定。
 */
@RestController
@RequestMapping("/api/admin/users")
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    @PutMapping("/roles")
    @RequirePermission("admin:manage")
    public UserView changeRoles(@RequestBody RoleChangeRequest request) {
        User updated = authService.changeRoles(request.userId(), request.roles());
        List<String> roles = updated.roles().stream().map(Enum::name).sorted().toList();
        return new UserView(updated.id(), updated.username(), roles, updated.enabled());
    }
}
