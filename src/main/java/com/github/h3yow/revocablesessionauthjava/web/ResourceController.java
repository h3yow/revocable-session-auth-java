package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.domain.AuthenticatedUser;
import com.github.h3yow.revocablesessionauthjava.security.SecurityContext;
import com.github.h3yow.revocablesessionauthjava.web.dto.AdminViewResponse;
import com.github.h3yow.revocablesessionauthjava.web.dto.ProfileResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源：使用角色聚合出的权限进行判定。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    /** 任何已认证且具备 profile:read 的角色均可访问。 */
    @GetMapping("/profile")
    @RequirePermission("profile:read")
    public ProfileResponse profile() {
        AuthenticatedUser user = SecurityContext.get();
        return new ProfileResponse(user.userId(), user.username(), user.sessionId());
    }

    /** 仅具备 admin:read 的角色可访问；普通用户得到 ACCESS_DENIED(403)。 */
    @GetMapping("/admin")
    @RequirePermission("admin:read")
    public AdminViewResponse admin() {
        AuthenticatedUser user = SecurityContext.get();
        return new AdminViewResponse("管理视图访问成功", user.username());
    }
}
