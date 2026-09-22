package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;

/**
 * 基于 ConcurrentHashMap 的内存会话存储。
 * 刷新令牌的单次使用由 {@link RefreshTokenRecord#used()} 的 CAS 保证，
 * 因此并发刷新时只有一个请求能抢占成功，与存储实现解耦。
 */
@Component
public class InMemorySessionStore implements SessionStore {

    private final ConcurrentMap<String, Session> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RefreshTokenRecord> refreshTokens = new ConcurrentHashMap<>();

    @Override
    public void saveSession(Session session) {
        sessions.put(session.id(), session);
    }

    @Override
    public Optional<Session> findSession(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    @Override
    public List<Session> findSessionsByUsername(String username) {
        return sessions.values().stream()
                .filter(s -> s.username().equals(username))
                .toList();
    }

    @Override
    public void saveRefreshToken(RefreshTokenRecord record) {
        refreshTokens.put(record.jti(), record);
    }

    @Override
    public Optional<RefreshTokenRecord> findRefreshToken(String jti) {
        return Optional.ofNullable(refreshTokens.get(jti));
    }

    @Override
    public void deleteRefreshToken(String jti) {
        refreshTokens.remove(jti);
    }

    @Override
    public void revokeSession(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session != null) {
            session.revoke();
        }
    }
}
