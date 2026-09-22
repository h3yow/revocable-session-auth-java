package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.Authentication;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 公开 / 已认证 / 管理员资源。 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public/ping")
    public Map<String, String> ping() {
        return Map.of("status", "ok");
    }

    @GetMapping("/user/profile")
    @RequirePermission("profile:read")
    public Map<String, Object> profile(HttpServletRequest request) {
        Authentication auth = AuthInterceptor.currentAuthentication(request);
        return Map.of(
                "message", "个人资料",
                "username", auth.username(),
                "sessionId", auth.sessionId(),
                "permissions", auth.permissions());
    }

    @GetMapping("/admin/stats")
    @RequirePermission("admin:stats")
    public Map<String, Object> stats(HttpServletRequest request) {
        Authentication auth = AuthInterceptor.currentAuthentication(request);
        return Map.of(
                "message", "管理员统计数据",
                "username", auth.username(),
                "roles", auth.roles());
    }
}
