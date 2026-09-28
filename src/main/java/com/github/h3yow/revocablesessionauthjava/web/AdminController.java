package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import com.github.h3yow.revocablesessionauthjava.auth.AuthService;
import com.github.h3yow.revocablesessionauthjava.auth.Permissions;
import com.github.h3yow.revocablesessionauthjava.auth.SessionAdminService;
import com.github.h3yow.revocablesessionauthjava.auth.SessionInfo;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 管理员会话治理与角色调整入口（均需 ADMIN 通配或对应细分权限）。
 * 对外响应只含稳定字段与固定结论，内部标识（jti 等）不返回；
 * 撤销类操作幂等，不存在的目标给出 404 + 稳定原因码。
 */
@RestController
public class AdminController {

    private final SessionAdminService sessionAdminService;
    private final AuthService authService;

    public AdminController(SessionAdminService sessionAdminService, AuthService authService) {
        this.sessionAdminService = sessionAdminService;
        this.authService = authService;
    }

    public record RoleChangeRequest(Set<String> roles) {
    }

    /** 查看某用户当前仍在生效的会话概览。 */
    @GetMapping("/api/admin/users/{username}/sessions")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> listSessions(@PathVariable String username) {
        List<SessionInfo> sessions = sessionAdminService.listActiveSessions(username);
        List<Map<String, Object>> items = sessions.stream()
                .map(AdminController::toView)
                .toList();
        return Map.of("username", username, "activeSessionCount", items.size(), "sessions", items);
    }

    /** 强制下线单条会话；不存在返回 404 session_not_found，重复下线幂等成功。 */
    @PostMapping("/api/admin/sessions/{sessionId}/revoke")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> revokeSession(@PathVariable String sessionId) {
        boolean exists = sessionAdminService.revokeSession(sessionId);
        if (!exists) {
            throw new AuthException(AuthFailureReason.SESSION_NOT_FOUND, "session id=" + sessionId);
        }
        return Map.of("status", "revoked", "sessionId", sessionId);
    }

    /** 强制下线某用户全部仍在生效的会话（幂等，返回本次新下线数量）。 */
    @PostMapping("/api/admin/users/{username}/sessions/revoke")
    @RequirePermission(Permissions.ADMIN_SESSIONS)
    public Map<String, Object> revokeAllSessions(@PathVariable String username) {
        int revokedCount = sessionAdminService.revokeAllSessions(username);
        return Map.of("status", "revoked", "username", username, "revokedSessionCount", revokedCount);
    }

    /** 调整某用户角色；变更立即对该用户已有会话生效（旧访问令牌下一次请求即失效）。 */
    @PostMapping("/api/admin/users/{username}/roles")
    @RequirePermission(Permissions.ADMIN_ROLES)
    public Map<String, Object> changeRoles(@PathVariable String username,
                                           @RequestBody RoleChangeRequest request) {
        Set<String> roles = request.roles() == null ? Set.of() : request.roles();
        authService.changeRoles(username, roles);
        return Map.of("status", "roles_updated", "username", username, "roles", roles);
    }

    private static Map<String, Object> toView(SessionInfo info) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("sessionId", info.sessionId());
        view.put("username", info.username());
        view.put("createdAtEpochMillis", info.createdAtEpochMillis());
        view.put("lastActiveAtEpochMillis", info.lastActiveAtEpochMillis());
        return view;
    }
}
