package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 管理员会话治理的默认实现。
 * <ul>
 *   <li>概览只返回仍在生效（未撤销）的会话，按创建时间排序；</li>
 *   <li>强制下线直接置会话 revoked=true，访问/刷新都实时回查该标志，因此立即生效；</li>
 *   <li>撤销与刷新换发共用 {@link Session} 对象监视器，二者互斥，
 *       撤销不可能被并发刷新"救活"，也不存在放行/撤销抢先后时好时坏；</li>
 *   <li>撤销操作幂等：会话不存在或已撤销时结果稳定，不抛底层错误。</li>
 * </ul>
 */
@Service
public class DefaultSessionAdminService implements SessionAdminService {

    private static final Logger log = LoggerFactory.getLogger(DefaultSessionAdminService.class);

    private final SessionStore sessionStore;

    public DefaultSessionAdminService(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    @Override
    public List<SessionInfo> listActiveSessions(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        return sessionStore.findSessionsByUsername(username).stream()
                .filter(session -> !session.revoked())
                .sorted(Comparator.comparingLong(Session::createdAtEpochMillis))
                .map(SessionInfo::of)
                .toList();
    }

    @Override
    public boolean revokeSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            log.info("强制下线单条会话结果 notFound basis=sessionId 为空");
            return false;
        }
        return sessionStore.findSession(sessionId)
                .map(session -> {
                    // revoke() 与刷新临界区互斥：
                    // 先撤销 -> 并发刷新在临界区内看到 revoked=true 被拒；
                    // 先签发 -> 新令牌随会话一起被撤销，立即不可用。
                    session.revoke();
                    log.info("强制下线单条会话结果 revoked basis=幂等置 revoked=true sessionId={} username={}",
                            session.id(), session.username());
                    return true;
                })
                .orElseGet(() -> {
                    log.info("强制下线单条会话结果 notFound basis=服务端无此会话登记 sessionId={}", sessionId);
                    return false;
                });
    }

    @Override
    public int revokeAllSessions(String username) {
        if (username == null || username.isBlank()) {
            return 0;
        }
        List<Session> sessions = sessionStore.findSessionsByUsername(username);
        int revoked = 0;
        for (Session session : sessions) {
            // 逐条与该会话的刷新临界区互斥，保证每条会话都满足上面的撤销一致性
            session.revoke();
            revoked++;
        }
        log.info("强制下线用户全部会话结果 revokedCount={} basis=遍历 {} 条会话幂等置 revoked username={}",
                revoked, sessions.size(), username);
        return revoked;
    }
}
