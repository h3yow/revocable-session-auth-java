package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;

/**
 * 对某用户全部会话强制下线的结果。
 *
 * @param username             被治理用户
 * @param revokedSessionCount  本次仍生效、被强制下线的会话数（已撤销的不计入）
 * @param sessionIds           被强制下线的会话标识
 */
public record UserRevocationResult(
        String username,
        int revokedSessionCount,
        List<String> sessionIds) {
}
