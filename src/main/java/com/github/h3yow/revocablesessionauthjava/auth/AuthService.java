package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 认证领域服务：登录、刷新（轮换 + 并发单次成功）、注销、访问校验。
 */
public interface AuthService {

    TokenPair login(String username, String password);

    TokenPair refresh(String rawRefreshToken);

    void logout(String rawRefreshToken);

    Authentication authenticateAccessToken(String rawAccessToken);

    void changeRoles(String username, java.util.Set<String> newRoles);
}
