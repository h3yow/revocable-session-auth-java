package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Set;

/**
 * 认证领域服务：登录、刷新（轮换 + 并发单次成功）、注销、访问校验、
 * 管理员会话治理（会话概览 / 单条或全部强制下线 / 角色调整）。
 */
public interface AuthService {

    TokenPair login(String username, String password);

    TokenPair refresh(String rawRefreshToken);

    void logout(String rawRefreshToken);

    Authentication authenticateAccessToken(String rawAccessToken);

    /** 变更用户角色：更新目录并提升该用户所有生效会话版本。用户不存在抛 USER_NOT_FOUND。 */
    int changeRoles(String username, Set<String> newRoles);

    /** 查看某用户当前仍生效的会话概览。用户不存在抛 USER_NOT_FOUND。 */
    SessionOverviewResponse listActiveSessions(String username);

    /** 对单条会话强制下线（幂等：不存在/重复撤销结果稳定，不产生底层错误）。 */
    SessionRevocationResult revokeSession(String sessionId);

    /** 对某用户全部生效会话强制下线；未被下线的其他会话不受影响。 */
    UserRevocationResult revokeUserSessions(String username);
}
