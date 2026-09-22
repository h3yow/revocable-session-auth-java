package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 令牌与访问控制的可区分失败类别。
 * 每种类别绑定对外 HTTP 状态码与不包含底层细节的安全提示信息。
 */
public enum TokenError {

    /** 凭证缺失 */
    MISSING_TOKEN(401, "缺少访问凭证"),
    /** 伪造：根本不具备令牌的合法结构 */
    FORGED_TOKEN(401, "令牌不是合法的签发结构"),
    /** 签名不匹配：结构合法但签名校验失败 */
    SIGNATURE_INVALID(401, "令牌签名校验失败"),
    /** 内容被篡改：载荷无法解析或缺少必要声明 */
    PAYLOAD_TAMPERED(401, "令牌内容无法解析或声明不完整"),
    /** 不支持的令牌类型（例如拿刷新令牌当访问令牌使用） */
    UNSUPPORTED_TOKEN(401, "不支持的令牌类型"),
    /** 令牌已过期 */
    EXPIRED_TOKEN(401, "令牌已过期"),
    /** 会话已注销或被撤销 */
    REVOKED_SESSION(401, "会话已被撤销"),
    /** 刷新令牌已轮换（旧令牌）或被重复使用 */
    REPLAYED_REFRESH_TOKEN(401, "刷新令牌已失效或被重复使用"),
    /** 检测到旧刷新令牌被重复使用（可能已泄露），整个令牌族已被撤销 */
    REUSE_DETECTED(401, "检测到刷新令牌被重复使用，会话族已撤销"),
    /** 会话不存在（无法在服务端状态中找到） */
    UNKNOWN_SESSION(401, "会话不存在或已终止"),
    /** 用户不存在或已被停用 */
    USER_UNAVAILABLE(401, "用户不可用"),
    /** 登录凭证错误 */
    BAD_CREDENTIALS(401, "用户名或密码错误"),
    /** 已认证但权限不足 */
    ACCESS_DENIED(403, "权限不足");

    private final int httpStatus;
    private final String publicMessage;

    TokenError(int httpStatus, String publicMessage) {
        this.httpStatus = httpStatus;
        this.publicMessage = publicMessage;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String publicMessage() {
        return publicMessage;
    }
}
