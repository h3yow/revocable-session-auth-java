package com.github.h3yow.revocablesessionauthjava.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.revocablesessionauthjava.support.AuthAssertions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * 管理员会话治理领域测试：会话概览、强制下线单条/全部、幂等与不存在目标、
 * 同用户其他会话不受牵连、撤销与并发刷新竞争下结论稳定。
 */
@SpringBootTest
@Import(TestClockConfig.class)
class SessionAdminServiceTest {

    private static final Logger log = AuthTestLogger.logger(SessionAdminServiceTest.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private SessionAdminService sessionAdminService;

    @Test
    @DisplayName("会话概览：列出未撤销会话（id/创建时间/最近活动时间），撤销后不再出现")
    void listActiveSessionsOverview() {
        TokenPair p1 = authService.login("alice", "alice123");
        Authentication a1 = authService.authenticateAccessToken(p1.accessToken());
        TokenPair p2 = authService.login("alice", "alice123");
        Authentication a2 = authService.authenticateAccessToken(p2.accessToken());

        List<SessionInfo> active = sessionAdminService.listActiveSessions("alice");
        AuthTestLogger.input(log, "alice 登录两次后查询会话概览 count={}", active.size());
        AuthTestLogger.basis(log, "概览只含未撤销会话，字段为 sessionId/创建时间/最近活动时间");
        // 存储中可能有其他用例留下的同用户会话；这里只断言本次两条都在且字段自洽
        assertTrue(active.size() >= 2);
        SessionInfo i1 = find(active, a1.sessionId());
        SessionInfo i2 = find(active, a2.sessionId());
        assertTrue(i1.createdAtEpochMillis() <= i2.createdAtEpochMillis());
        assertTrue(i1.lastActiveAtEpochMillis() >= i1.createdAtEpochMillis());
        AuthTestLogger.result(log, "两条会话均在概览中，时间字段自洽");

        sessionAdminService.revokeSession(a1.sessionId());
        List<SessionInfo> after = sessionAdminService.listActiveSessions("alice");
        AuthTestLogger.basis(log, "强制下线第一条后再查概览");
        assertTrue(after.stream().noneMatch(s -> s.sessionId().equals(a1.sessionId())));
        assertTrue(after.stream().anyMatch(s -> s.sessionId().equals(a2.sessionId())));
        AuthTestLogger.result(log, "被下线会话消失，另一条仍在");
    }

    @Test
    @DisplayName("强制下线单条：访问/刷新立即失效；同用户另一条会话照常可用")
    void revokeOneSessionDoesNotAffectOthers() {
        TokenPair victim = authService.login("alice", "alice123");
        TokenPair other = authService.login("alice", "alice123");
        Authentication victimAuth = authService.authenticateAccessToken(victim.accessToken());
        Authentication otherAuth = authService.authenticateAccessToken(other.accessToken());
        AuthTestLogger.input(log, "alice 两条会话，强制下线 sessionId={}", victimAuth.sessionId());

        assertTrue(sessionAdminService.revokeSession(victimAuth.sessionId()));

        AuthTestLogger.basis(log, "被下线会话访问实时回查 revoked=true -> SESSION_REVOKED");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(victim.accessToken()));
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.refresh(victim.refreshToken()));

        AuthTestLogger.basis(log, "同一用户另一条会话的访问与刷新不受牵连");
        Authentication stillAuth = authService.authenticateAccessToken(other.accessToken());
        assertEquals(otherAuth.sessionId(), stillAuth.sessionId());
        TokenPair rotated = authService.refresh(other.refreshToken());
        assertTrue(authService.authenticateAccessToken(rotated.accessToken()).permissions()
                .contains(Permissions.PROFILE_READ));
        AuthTestLogger.result(log, "另一条会话访问/刷新均 SUCCESS");
    }

    @Test
    @DisplayName("强制下线幂等：不存在会话返回 false 且稳定；重复撤销同一条结果可重复")
    void revokeIsIdempotentAndStable() {
        AuthTestLogger.input(log, "对不存在的 sessionId 反复强制下线");
        for (int i = 0; i < 3; i++) {
            assertFalse(sessionAdminService.revokeSession("sess-does-not-exist-" + i));
        }
        assertFalse(sessionAdminService.revokeSession("  "));
        AuthTestLogger.result(log, "不存在/空 sessionId 一律稳定返回 false，无底层错误");

        TokenPair pair = authService.login("alice", "alice123");
        Authentication auth = authService.authenticateAccessToken(pair.accessToken());
        assertTrue(sessionAdminService.revokeSession(auth.sessionId()));
        for (int i = 0; i < 3; i++) {
            assertTrue(sessionAdminService.revokeSession(auth.sessionId()), "重复撤销同一条会话结果稳定为 true");
        }
        AuthTestLogger.result(log, "重复下线同一条会话结论可重复");
    }

    @Test
    @DisplayName("强制下线用户全部会话：名下所有会话立即失效，反复调用幂等")
    void revokeAllSessionsForUser() {
        TokenPair a = authService.login("alice", "alice123");
        TokenPair b = authService.login("alice", "alice123");
        TokenPair adminPair = authService.login("admin", "admin123");
        Authentication aa = authService.authenticateAccessToken(a.accessToken());
        Authentication bb = authService.authenticateAccessToken(b.accessToken());
        Authentication adm = authService.authenticateAccessToken(adminPair.accessToken());

        int count = sessionAdminService.revokeAllSessions("alice");
        AuthTestLogger.input(log, "强制下线 alice 全部会话，返回撤销数={}", count);
        assertTrue(count >= 2, "应覆盖本次两条会话（可能含同用户历史会话）");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(a.accessToken()));
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(b.accessToken()));
        assertTrue(sessionAdminService.listActiveSessions("alice").stream()
                .noneMatch(s -> s.sessionId().equals(aa.sessionId()) || s.sessionId().equals(bb.sessionId())));

        AuthTestLogger.basis(log, "不牵连其他用户：admin 的会话照常");
        assertTrue(authService.authenticateAccessToken(adminPair.accessToken()).permissions()
                .contains(Permissions.WILDCARD));
        assertEquals(adm.sessionId(), authService.authenticateAccessToken(adminPair.accessToken()).sessionId());

        int again = sessionAdminService.revokeAllSessions("alice");
        AuthTestLogger.result(log, "再次调用幂等撤销数={}，admin 不受影响", again);
        assertTrue(again >= 2, "幂等：名下会话仍被计数为已撤销，不抛错");
    }

    @Test
    @DisplayName("并发：撤销与刷新赛跑，刷新要么被拒、要么新令牌在撤销落地后立即失效，绝无救活")
    void concurrentRevokeVsRefreshNeverRevives() throws Exception {
        int rounds = 30;
        int refreshThreads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(refreshThreads + 1);
        AtomicInteger rejected = new AtomicInteger();
        // 每轮收集刷新线程观察到的"换发成功"次数与其新访问令牌（join 后再统一验证）
        List<String> rotatedTokens = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        AtomicInteger refreshSuccess = new AtomicInteger();

        for (int round = 0; round < rounds; round++) {
            rotatedTokens.clear();
            refreshSuccess.set(0);
            TokenPair pair = authService.login("alice", "alice123");
            Authentication auth = authService.authenticateAccessToken(pair.accessToken());
            String sessionId = auth.sessionId();
            String refreshToken = pair.refreshToken();

            CountDownLatch ready = new CountDownLatch(refreshThreads + 1);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new java.util.ArrayList<>();

            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                sessionAdminService.revokeSession(sessionId);
                return null;
            }));
            for (int t = 0; t < refreshThreads; t++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    try {
                        TokenPair rotated = authService.refresh(refreshToken);
                        refreshSuccess.incrementAndGet();
                        rotatedTokens.add(rotated.accessToken());
                    } catch (AuthException e) {
                        // 撤销先生效 / CAS 竞争失败，均为稳定拒绝
                        if (e.reason() == AuthFailureReason.SESSION_REVOKED
                                || e.reason() == AuthFailureReason.REFRESH_TOKEN_REUSED) {
                            rejected.incrementAndGet();
                        } else {
                            throw e;
                        }
                    }
                    return null;
                }));
            }
            ready.await();
            start.countDown();
            // 等待所有线程（含撤销线程）结束 —— 此刻撤销必定已经落地
            for (Future<?> f : futures) {
                f.get();
            }

            // CAS 抢占：无论撤销如何竞争，每轮至多一次刷新成功
            assertTrue(refreshSuccess.get() <= 1, "同一刷新令牌每轮至多换发成功一次");

            // 关键不变量：撤销落地后，原访问令牌以及任何"抢在撤销前换发"的新令牌都必须立即失效，
            // 不存在撤销被刷新救活的窗口（刷新在撤销前线性化是合法的，但产物在撤销后必须死）
            AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                    () -> authService.authenticateAccessToken(pair.accessToken()));
            for (String rotatedAccess : rotatedTokens) {
                AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                        () -> authService.authenticateAccessToken(rotatedAccess));
            }
        }
        pool.shutdown();
        AuthTestLogger.result(log, "{} 轮全部满足：换发成功均在撤销落地后立即失效，稳定拒绝={} 次",
                rounds, rejected.get());
    }

    private static SessionInfo find(List<SessionInfo> sessions, String sessionId) {
        return sessions.stream()
                .filter(s -> s.sessionId().equals(sessionId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("概览中缺少会话 " + sessionId));
    }
}
