package com.github.h3yow.revocablesessionauthjava.auth;

/** 一次签发或轮换产出的令牌对。 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessTokenExpiresInSeconds) {
}
