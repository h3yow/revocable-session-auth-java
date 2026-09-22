package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 刷新令牌轮换的原子结果。
 */
public record RotationOutcome(Kind kind, Session session, String nextRefreshJti) {

    public enum Kind {
        /** 轮换成功，nextRefreshJti 为新刷新令牌标识 */
        OK,
        /** 会话不存在 */
        UNKNOWN,
        /** 会话此前已撤销 */
        REVOKED,
        /** 旧/未知刷新令牌被重复使用，会话族已被连带撤销 */
        REPLAYED
    }

    public static RotationOutcome ok(Session session, String nextRefreshJti) {
        return new RotationOutcome(Kind.OK, session, nextRefreshJti);
    }

    public static RotationOutcome unknown() {
        return new RotationOutcome(Kind.UNKNOWN, null, null);
    }

    public static RotationOutcome revoked(Session session) {
        return new RotationOutcome(Kind.REVOKED, session, null);
    }

    public static RotationOutcome replayed(Session session) {
        return new RotationOutcome(Kind.REPLAYED, session, null);
    }
}
