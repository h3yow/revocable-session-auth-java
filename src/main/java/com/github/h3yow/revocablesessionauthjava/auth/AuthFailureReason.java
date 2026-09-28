package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 鉴权失败的可区分分类。对外只暴露 {@link #code()} 与稳定描述，
 * 不暴露任何底层异常细节。
 */
public enum AuthFailureReason {

    MISSING_TOKEN("missing_token", "缺少访问令牌"),
    MALFORMED_TOKEN("malformed_token", "令牌格式不合法"),
    INVALID_SIGNATURE("invalid_signature", "令牌签名无效或内容已被篡改"),
    WRONG_TOKEN_TYPE("wrong_token_type", "令牌类型与使用场景不匹配"),
    EXPIRED("expired_token", "令牌已过期"),
    SESSION_REVOKED("session_revoked", "会话已被撤销"),
    SESSION_STATE_CHANGED("session_state_changed", "会话状态已变更，旧令牌不再有效"),
    REFRESH_TOKEN_REUSED("refresh_token_reused", "刷新令牌已被使用，不能重复换取"),
    UNKNOWN_TOKEN("unknown_token", "令牌不存在或已失效"),
    SESSION_NOT_FOUND("session_not_found", "服务端不存在该会话"),
    TOKEN_SESSION_MISMATCH("token_session_mismatch", "令牌与当前会话或用户不匹配"),
    ACCESS_DENIED("access_denied", "权限不足"),
    BAD_CREDENTIALS("bad_credentials", "用户名或密码错误"),
    USER_NOT_FOUND("user_not_found", "用户不存在");

    private final String code;
    private final String description;

    AuthFailureReason(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }
}
