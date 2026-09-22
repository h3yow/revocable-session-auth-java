package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 令牌载荷声明。
 * typ: AT=短期访问令牌，RT=长期刷新令牌
 */
public record TokenClaims(String type, String subject, String sessionId,
                          String jti, long issuedAt, long expiresAt) {

    public static final String TYPE_ACCESS = "AT";
    public static final String TYPE_REFRESH = "RT";
}
