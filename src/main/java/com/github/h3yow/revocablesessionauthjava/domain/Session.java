package com.github.h3yow.revocablesessionauthjava.domain;

/**
 * 会话聚合（不可变快照）。
 * currentRefreshJti 为当前唯一有效的刷新令牌标识；轮换时整体替换。
 * revoked=true 后，该会话此前签发的全部访问令牌立即失效。
 */
public record Session(String id, String userId, String currentRefreshJti,
                      boolean revoked, TokenError revokeReason) {
}
