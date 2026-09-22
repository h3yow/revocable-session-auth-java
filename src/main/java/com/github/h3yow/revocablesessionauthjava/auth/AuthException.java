package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 鉴权领域异常。reason 用于对外分类，internalDetail 仅写入服务端日志，不返回调用方。
 */
public class AuthException extends RuntimeException {

    private final AuthFailureReason reason;
    private final String internalDetail;

    public AuthException(AuthFailureReason reason, String internalDetail) {
        super(reason.code() + ": " + internalDetail);
        this.reason = reason;
        this.internalDetail = internalDetail;
    }

    public AuthFailureReason reason() {
        return reason;
    }

    public String internalDetail() {
        return internalDetail;
    }
}
