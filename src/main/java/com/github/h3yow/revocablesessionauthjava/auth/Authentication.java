package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Set;

/**
 * 访问令牌通过校验后得到的认证主体。
 * 角色与权限在每次请求时从会话存储实时读取，保证权限变更立即生效。
 */
public record Authentication(
        String username,
        String sessionId,
        String tokenId,
        Set<String> roles,
        Set<String> permissions) {
}
