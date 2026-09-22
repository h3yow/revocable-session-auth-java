package com.github.h3yow.revocablesessionauthjava.security.session;

import com.github.h3yow.revocablesessionauthjava.domain.RotationOutcome;
import com.github.h3yow.revocablesessionauthjava.domain.Session;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话存储（本地内存实现）。
 *
 * <p>所有读-改-写都通过 {@link ConcurrentHashMap#compute} 以<b>原子</b>方式完成，
 * 同一 sessionId 的判定在 Map 的 bin 锁内串行执行，因此同一刷新令牌在并发请求下
 * 至多成功轮换一次；旧令牌（含被窃取后重放的令牌）再次出现会连带撤销整个会话族。
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    /** 登录时保存全新会话。 */
    public void save(Session session) {
        sessions.put(session.id(), session);
    }

    public Session findById(String sessionId) {
        return sessions.get(sessionId);
    }

    /**
     * 原子轮换刷新令牌。
     *
     * @param sessionId    令牌中声明的会话标识
     * @param presentedJti 请求中出示的刷新令牌标识
     * @param nextJti      新刷新令牌标识
     * @return 轮换结果：OK / UNKNOWN / REVOKED / REPLAYED
     */
    public RotationOutcome rotate(String sessionId, String presentedJti, String nextJti) {
        @SuppressWarnings("unchecked")
        RotationOutcome[] outcome = new RotationOutcome[1];
        sessions.compute(sessionId, (id, current) -> {
            if (current == null) {
                outcome[0] = RotationOutcome.unknown();
                return null;
            }
            if (current.revoked()) {
                outcome[0] = RotationOutcome.revoked(current);
                return current;
            }
            if (!current.currentRefreshJti().equals(presentedJti)) {
                // 旧令牌/未知令牌重放：安全语义上视为可能已泄露，撤销整个会话族
                Session revoked = new Session(current.id(), current.userId(), current.currentRefreshJti(),
                        true, TokenError.REUSE_DETECTED);
                outcome[0] = RotationOutcome.replayed(revoked);
                return revoked;
            }
            Session rotated = new Session(current.id(), current.userId(), nextJti, false, null);
            outcome[0] = RotationOutcome.ok(rotated, nextJti);
            return rotated;
        });
        return outcome[0];
    }

    /** 主动注销 / 管理端撤销。此后该会话签发的访问令牌立即失效。 */
    public void revoke(String sessionId) {
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (current.revoked()) {
                return current;
            }
            return new Session(current.id(), current.userId(), current.currentRefreshJti(),
                    true, TokenError.REVOKED_SESSION);
        });
    }
}
