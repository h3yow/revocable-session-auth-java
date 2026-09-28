package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 认证领域服务：登录、刷新（轮换 + 并发单次成功）、注销、访问校验。
 */
public interface AuthService {

    TokenPair login(String username, String password);

    TokenPair refresh(String rawRefreshToken);

    void logout(String rawRefreshToken);

    Authentication authenticateAccessToken(String rawAccessToken);

    /** 调整用户角色：更新账户目录并提升其全部会话版本，返回账户是否存在与受影响会话数。 */
    RoleChangeResult changeRoles(String username, java.util.Set<String> newRoles);
}
