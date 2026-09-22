package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;
import java.util.Optional;

/**
 * 会话与刷新令牌的服务端状态存储（本地内存实现）。
 * 所有访问令牌的校验都实时查询这里，因此撤销/权限变更即时生效，不存在缓存放行窗口。
 */
public interface SessionStore {

    void saveSession(Session session);

    Optional<Session> findSession(String sessionId);

    List<Session> findSessionsByUsername(String username);

    void saveRefreshToken(RefreshTokenRecord record);

    Optional<RefreshTokenRecord> findRefreshToken(String jti);

    void deleteRefreshToken(String jti);

    void revokeSession(String sessionId);
}
