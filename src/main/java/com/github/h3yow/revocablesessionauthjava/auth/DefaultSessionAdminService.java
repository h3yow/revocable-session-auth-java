package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 默认管理员会话治理服务。
 * <ul>
 *   <li>概览只返回仍在生效（未撤销）的会话，字段稳定可对外暴露；</li>
 *   <li>撤销调用 {@link Session#revokeIfActive()}，该方法与刷新换发共用会话监视器，
 *       强制下线与"判定未撤销+签发新令牌"互斥，不会出现撤销后被刷新救活；</li>
 *   <li>撤销即时生效：访问令牌每次请求实时回查会话，revoked=true 立即拒绝，
 *       该会话此前签发的刷新令牌同样无法再换取；</li>
 *   <li>全部操作幂等：已撤销会话重复撤销不报错、计数稳定；只精确作用于目标，
 *       同用户其他会话不受牵连。</li>
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
        List<SessionInfo> infos = sessionStore.findSessionsByUsername(username).stream()
                .filter(session -> !session.revoked())
                .map(SessionInfo::of)
                .toList();
        log.info("会话概览 username={} activeCount={}", username, infos.size());
        return infos;
    }

    @Override
    public boolean revokeSession(String sessionId) {
        Session session = sessionStore.findSession(sessionId).orElse(null);
        if (session == null) {
            log.info("单条强制下线结果 reason=SESSION_NOT_FOUND basis=服务端无此会话 sessionId={}", sessionId);
            return false;
        }
        boolean newlyRevoked = session.revokeIfActive();
        if (newlyRevoked) {
            log.info("单条强制下线结果 SUCCESS basis=会话状态翻转为 revoked sessionId={} username={}",
                    sessionId, session.username());
        } else {
            log.info("单条强制下线结果 SUCCESS(幂等) basis=会话此前已撤销 sessionId={} username={}",
                    sessionId, session.username());
        }
        return true;
    }

    @Override
    public int revokeAllSessions(String username) {
        List<Session> sessions = sessionStore.findSessionsByUsername(username);
        int newlyRevoked = 0;
        for (Session session : sessions) {
            if (session.revokeIfActive()) {
                newlyRevoked++;
            }
        }
        log.info("全部强制下线结果 username={} totalSessions={} newlyRevoked={}",
                username, sessions.size(), newlyRevoked);
        return newlyRevoked;
    }
}
