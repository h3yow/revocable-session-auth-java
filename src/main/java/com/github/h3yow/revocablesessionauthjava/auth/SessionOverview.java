package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 管理员看到的单条生效会话概览。只含稳定的会话标识与时间信息，
 * 不包含令牌原文、内部刷新令牌登记标识等敏感内部细节。
 *
 * @param sessionId                会话标识
 * @param createdAtEpochMillis     创建时间（epoch millis）
 * @param lastActivityAtEpochMillis 最近活动时间（登录/刷新，epoch millis）
 */
public record SessionOverview(
        String sessionId,
        long createdAtEpochMillis,
        long lastActivityAtEpochMillis) {

    static SessionOverview from(Session session) {
        return new SessionOverview(
                session.id(), session.createdAtEpochMillis(), session.lastActivityAtEpochMillis());
    }
}
