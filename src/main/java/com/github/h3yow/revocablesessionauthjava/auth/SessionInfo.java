package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 会话概览（面向管理员）。只含对外可暴露的稳定字段，
 * 不含角色集合之外的任何内部实现细节。
 */
public record SessionInfo(
        String sessionId,
        String username,
        long createdAtEpochMillis,
        long lastActiveAtEpochMillis) {

    static SessionInfo of(Session session) {
        return new SessionInfo(session.id(), session.username(),
                session.createdAtEpochMillis(), session.lastActiveAtEpochMillis());
    }
}
