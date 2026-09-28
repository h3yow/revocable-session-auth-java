package com.github.h3yow.revocablesessionauthjava.auth;

import org.springframework.http.HttpStatus;

/**
 * 鉴权失败的可区分分类。对外只暴露 {@link #code()} 与稳定描述，
 * 不暴露任何底层异常细节。
 */
public enum AuthFailureReason {

    MISSING_TOKEN("missing_token", "缺少访问令牌", HttpStatus.UNAUTHORIZED),
    MALFORMED_TOKEN("malformed_token", "令牌格式不合法", HttpStatus.UNAUTHORIZED),
    INVALID_SIGNATURE("invalid_signature", "令牌签名无效", HttpStatus.UNAUTHORIZED),
    TAMPERED_TOKEN("tampered_token", "令牌内容已被篡改", HttpStatus.UNAUTHORIZED),
    SESSION_TOKEN_MISMATCH("session_token_mismatch", "令牌与服务端会话记录不一致", HttpStatus.UNAUTHORIZED),
    WRONG_TOKEN_TYPE("wrong_token_type", "令牌类型与使用场景不匹配", HttpStatus.UNAUTHORIZED),
    EXPIRED("expired_token", "令牌已过期", HttpStatus.UNAUTHORIZED),
    SESSION_REVOKED("session_revoked", "会话已被撤销", HttpStatus.UNAUTHORIZED),
    SESSION_STATE_CHANGED("session_state_changed", "会话状态已变更，旧令牌不再有效", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REUSED("refresh_token_reused", "刷新令牌已被使用，不能重复换取", HttpStatus.UNAUTHORIZED),
    UNKNOWN_TOKEN("unknown_token", "令牌不存在或已失效", HttpStatus.UNAUTHORIZED),
    ACCESS_DENIED("access_denied", "权限不足", HttpStatus.FORBIDDEN),
    BAD_CREDENTIALS("bad_credentials", "用户名或密码错误", HttpStatus.UNAUTHORIZED),
    USER_NOT_FOUND("user_not_found", "目标用户不存在", HttpStatus.NOT_FOUND),
    SESSION_NOT_FOUND("session_not_found", "目标会话不存在", HttpStatus.NOT_FOUND);

    private final String code;
    private final String description;
    private final HttpStatus httpStatus;

    AuthFailureReason(String code, String description, HttpStatus httpStatus) {
        this.code = code;
        this.description = description;
        this.httpStatus = httpStatus;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
