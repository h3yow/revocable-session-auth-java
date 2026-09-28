package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;

/**
 * 面向管理员的会话治理能力：
 * 查看某用户仍在生效的会话概览、强制下线单条会话、强制下线某用户全部会话。
 * 所有撤销操作幂等：目标不存在或已撤销时返回稳定结果，不抛出底层错误。
 */
public interface SessionAdminService {

    /** 某用户当前仍在生效（未撤销）的会话概览。 */
    List<SessionInfo> listActiveSessions(String username);

    /**
     * 强制下线单条会话。该会话已签发的访问/刷新令牌立即失效，不影响同用户其他会话。
     *
     * @return true 表示会话存在且已撤销（含此前已撤销）；false 表示会话不存在
     */
    boolean revokeSession(String sessionId);

    /**
     * 强制下线某用户全部会话（含已撤销的，幂等）。
     *
     * @return 本次调用时该用户名下被标记撤销的会话数量
     */
    int revokeAllSessions(String username);
}
