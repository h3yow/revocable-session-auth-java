package com.github.h3yow.revocablesessionauthjava.token;

import com.github.h3yow.revocablesessionauthjava.auth.TokenType;

/**
 * 令牌的声明内容（由签发端写入，校验端读取）。
 *
 * @param tokenId     令牌唯一标识（刷新令牌用于服务端登记/去重）
 * @param sessionId   所属服务端会话
 * @param username    主体
 * @param type        ACCESS / REFRESH
 * @param version     签发时的会话版本（访问令牌据此检测权限变更）
 * @param issuedAt    签发时间（epoch millis）
 * @param expiresAt   过期时间（epoch millis）
 */
public record TokenClaims(
        String tokenId,
        String sessionId,
        String username,
        TokenType type,
        long version,
        long issuedAt,
        long expiresAt) {
}
