package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;

/**
 * 某用户当前生效会话的概览结果。
 *
 * @param username           被查询用户
 * @param activeSessionCount 生效会话数
 * @param sessions           各会话概览（创建时间/最近活动时间）
 */
public record SessionOverviewResponse(
        String username,
        int activeSessionCount,
        List<SessionOverview> sessions) {
}
