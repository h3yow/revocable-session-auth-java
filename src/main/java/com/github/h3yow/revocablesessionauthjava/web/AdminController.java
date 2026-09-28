package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.AuthService;
import com.github.h3yow.revocablesessionauthjava.auth.Permissions;
import com.github.h3yow.revocablesessionauthjava.auth.RoleChangeResult;
import com.github.h3yow.revocablesessionauthjava.auth.SessionAdminService;
import com.github.h3yow.revocablesessionauthjava.auth.SessionInfo;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 管理员会话治理接口（均需 {@link Permissions#ADMIN_SESSIONS}，ADMIN 角色通配命中）：
 * <ul>
 *   <li>查看某用户当前仍在生效的会话概览；</li>
 *   <li>强制下线指定会话 / 某用户全部会话（幂等，结果稳定）；</li>
 *   <li>调整某用户角色，旧访问令牌在下一次请求即按最新角色判定。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final SessionAdminService sessionAdminService;
    private final AuthService authService;

    public AdminController(SessionAdminService sessionAdminService, AuthService authService) {
        this.sessionAdminService = sessionAdminService;
        this.authService = authService;
    }

    public record RoleChangeRequest(java.util.Set<String> roles) {
    }

    @GetMapping("/users/{username}/sessions")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> listSessions(@PathVariable String username) {
        List<SessionInfo> sessions = sessionAdminService.listActiveSessions(username);
        return Map.of(
                "username", username,
                "activeSessionCount", sessions.size(),
                "sessions", sessions);
    }

    @PostMapping("/sessions/{sessionId}/revoke")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> revokeSession(@PathVariable String sessionId) {
        boolean found = sessionAdminService.revokeSession(sessionId);
        // 不存在 / 已撤销都返回稳定结论，不抛 4xx 底层错误
        return Map.of(
                "sessionId", sessionId,
                "status", found ? "revoked" : "not_found");
    }

    @PostMapping("/users/{username}/sessions/revoke-all")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> revokeAllSessions(@PathVariable String username) {
        int revokedCount = sessionAdminService.revokeAllSessions(username);
        return Map.of(
                "username", username,
                "revokedSessionCount", revokedCount,
                "status", "revoked");
    }

    @PostMapping("/users/{username}/roles")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> changeRoles(@PathVariable String username,
                                           @RequestBody RoleChangeRequest request) {
        RoleChangeResult result = authService.changeRoles(
                username, request == null ? java.util.Set.of() : request.roles());
        return Map.of(
                "username", username,
                "accountFound", result.accountFound(),
                "updatedSessionCount", result.sessionsUpdated(),
                "status", result.accountFound() ? "updated" : "user_not_found");
    }
}
