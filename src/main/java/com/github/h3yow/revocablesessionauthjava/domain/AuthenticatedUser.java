package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 一次请求中解析出的认证主体（已通过会话与用户实时状态校验）。
 */
public record AuthenticatedUser(String userId, String username, String sessionId) {
}
