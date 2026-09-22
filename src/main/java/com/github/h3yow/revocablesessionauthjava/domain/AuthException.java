package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 鉴权领域异常：只携带可对外解释的失败类别，不携带任何底层异常细节。
 */
public class AuthException extends RuntimeException {

    private final TokenError error;

    public AuthException(TokenError error) {
        super(error.publicMessage());
        this.error = error;
    }

    public TokenError error() {
        return error;
    }
}
