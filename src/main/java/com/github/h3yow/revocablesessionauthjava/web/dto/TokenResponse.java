package com.github.h3yow.revocablesessionauthjava.web.dto;

import com.github.h3yow.revocablesessionauthjava.domain.TokenPair;

public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {

    public static TokenResponse from(TokenPair pair) {
        return new TokenResponse(pair.accessToken(), pair.refreshToken(), "Bearer", pair.expiresInSeconds());
    }
}
