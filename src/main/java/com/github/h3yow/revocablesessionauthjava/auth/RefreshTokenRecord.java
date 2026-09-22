package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 服务端登记的刷新令牌。used 通过 CAS 抢占，保证并发刷新只有一次成功。
 */
public final class RefreshTokenRecord {

    private final String jti;
    private final String sessionId;
    private final long expiresAtEpochMillis;
    private final AtomicBoolean used = new AtomicBoolean(false);

    public RefreshTokenRecord(String jti, String sessionId, long expiresAtEpochMillis) {
        this.jti = jti;
        this.sessionId = sessionId;
        this.expiresAtEpochMillis = expiresAtEpochMillis;
    }

    public String jti() { return jti; }
    public String sessionId() { return sessionId; }
    public long expiresAtEpochMillis() { return expiresAtEpochMillis; }
    public AtomicBoolean used() { return used; }
}
