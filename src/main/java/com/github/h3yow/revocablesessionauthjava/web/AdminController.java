package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.AuthService;
import com.github.h3yow.revocablesessionauthjava.auth.SessionOverviewResponse;
import com.github.h3yow.revocablesessionauthjava.auth.SessionRevocationResult;
import com.github.h3yow.revocablesessionauthjava.auth.UserRevocationResult;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 面向管理员的会话治理接口（均需 admin:session 权限，ADMIN 通配命中）：
 * 会话概览、单条/全部强制下线、角色调整。所有失败由 ApiExceptionHandler 统一分类输出。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    /** 角色调整请求体；roles 缺省视为清空角色。 */
    public record ChangeRolesRequest(List<String> roles) {
    }

    @GetMapping("/users/{username}/sessions")
    @RequirePermission("admin:session")
    public SessionOverviewResponse listSessions(@PathVariable String username) {
        return authService.listActiveSessions(username);
    }

    @PostMapping("/sessions/{sessionId}/revoke")
    @RequirePermission("admin:session")
    public SessionRevocationResult revokeSession(@PathVariable String sessionId) {
        return authService.revokeSession(sessionId);
    }

    @PostMapping("/users/{username}/sessions/revoke")
    @RequirePermission("admin:session")
    public UserRevocationResult revokeUserSessions(@PathVariable String username) {
        return authService.revokeUserSessions(username);
    }

    @PostMapping("/users/{username}/roles")
    @RequirePermission("admin:session")
    public Map<String, Object> changeRoles(@PathVariable String username,
                                           @RequestBody ChangeRolesRequest request) {
        List<String> requested = request.roles() == null
                ? List.of()
                : request.roles().stream().filter(r -> r != null && !r.isBlank()).toList();
        int affected = authService.changeRoles(username, java.util.Set.copyOf(requested));
        return Map.of(
                "username", username,
                "roles", requested,
                "affectedSessions", affected);
    }
}
