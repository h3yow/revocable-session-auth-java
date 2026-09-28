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

    /** 查询用户当前仍生效（未撤销）的会话，供管理员会话概览使用。 */
    List<Session> findActiveSessionsByUsername(String username);

    void saveRefreshToken(RefreshTokenRecord record);

    Optional<RefreshTokenRecord> findRefreshToken(String jti);

    void deleteRefreshToken(String jti);

    /**
     * 撤销指定会话。幂等：会话不存在返回 false；会话存在（无论此前是否已撤销）返回 true，
     * 重复撤销不会产生底层错误。
     */
    boolean revokeSession(String sessionId);
}
