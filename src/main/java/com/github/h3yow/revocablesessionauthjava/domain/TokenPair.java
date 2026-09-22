package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 一次登录或刷新后签发的令牌对。expiresInSeconds 为访问令牌有效期。
 */
public record TokenPair(String accessToken, String refreshToken, long expiresInSeconds) {
}
