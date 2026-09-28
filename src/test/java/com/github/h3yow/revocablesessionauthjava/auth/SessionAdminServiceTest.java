package com.github.h3yow.revocablesessionauthjava.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * 管理员会话治理领域测试：会话概览、单条/全部强制下线、幂等与不存在目标的稳定结果，
 * 以及"撤销 vs 并发刷新 / 并发访问"下撤销必定最终生效、不会被刷新救活。
 */
@SpringBootTest
@Import(TestClockConfig.class)
class SessionAdminServiceTest {

    private static final Logger log = AuthTestLogger.logger(SessionAdminServiceTest.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private SessionAdminService adminService;

    @Test
    @DisplayName("会话概览：返回生效会话数量/标识/创建与最近活动时间，撤销后不再出现")
    void overviewListsActiveSessions() {
        TokenPair p1 = authService.login("alice", "alice123");
        TokenPair p2 = authService.login("alice", "alice123");
        String id1 = authService.authenticateAccessToken(p1.accessToken()).sessionId();
        authService.authenticateAccessToken(p2.accessToken()); // 推进 id2 最近活动时间

        List<SessionInfo> infos = adminService.listActiveSessions("alice");
        AuthTestLogger.result(log, "概览 activeCount={}", infos.size());
        assertTrue(infos.size() >= 2);
        SessionInfo target = infos.stream().filter(i -> i.sessionId().equals(id1)).findFirst().orElseThrow();
        assertEquals("alice", target.username());
        assertTrue(target.createdAtEpochMillis() > 0);
        assertTrue(target.lastActiveAtEpochMillis() >= target.createdAtEpochMillis());

        adminService.revokeSession(id1);
        List<SessionInfo> after = adminService.listActiveSessions("alice");
        assertFalse(after.stream().anyMatch(i -> i.sessionId().equals(id1)));
        AuthTestLogger.result(log, "撤销后概览不再包含该会话 remaining={}", after.size());
    }

    @Test
    @DisplayName("单条强制下线：该会话访问/刷新立即失效；同用户其他会话照常可用")
    void revokeOneKillsOnlyThatSession() {
        TokenPair p1 = authService.login("alice", "alice123");
        TokenPair p2 = authService.login("alice", "alice123");
        String id1 = authService.authenticateAccessToken(p1.accessToken()).sessionId();
        String id2 = authService.authenticateAccessToken(p2.accessToken()).sessionId();

        assertTrue(adminService.revokeSession(id1));
        AuthTestLogger.input(log, "强制下线会话 id1={}，保留 id2={}", id1, id2);

        AuthTestLogger.basis(log, "访问实时回查 revoked=true；刷新在会话临界区内判定撤销");
        assertReason(AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(p1.accessToken()));
        assertReason(AuthFailureReason.SESSION_REVOKED,
                () -> authService.refresh(p1.refreshToken()));

        AuthTestLogger.result(log, "id2 未被牵连：访问与刷新均成功");
        Authentication auth2 = authService.authenticateAccessToken(p2.accessToken());
        assertEquals(id2, auth2.sessionId());
        TokenPair rotated2 = authService.refresh(p2.refreshToken());
        assertTrue(Permissions.satisfies(
                authService.authenticateAccessToken(rotated2.accessToken()).permissions(),
                new String[]{Permissions.PROFILE_READ}));
    }

    @Test
    @DisplayName("全部强制下线：该用户所有会话令牌失效，其他用户不受影响；重复调用计数为 0")
    void revokeAllKillsUserOnlyAndIsIdempotent() {
        TokenPair a1 = authService.login("alice", "alice123");
        TokenPair a2 = authService.login("alice", "alice123");
        TokenPair other = authService.login("admin", "admin123");

        int activeBefore = adminService.listActiveSessions("alice").size();
        int count = adminService.revokeAllSessions("alice");
        AuthTestLogger.result(log, "alice 下线前活跃={} 本次新下线会话数={}", activeBefore, count);
        assertTrue(activeBefore >= 2);
        assertEquals(activeBefore, count, "全部下线必须覆盖当时所有活跃会话");
        assertEquals(0, adminService.listActiveSessions("alice").size(), "下线后概览为空");

        assertReason(AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(a1.accessToken()));
        assertReason(AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(a2.accessToken()));
        assertEquals("admin", authService.authenticateAccessToken(other.accessToken()).username());

        assertEquals(0, adminService.revokeAllSessions("alice"), "重复全部下线：本次新下线数必须为 0");
        assertEquals(0, adminService.revokeAllSessions("ghost-user"), "不存在用户：稳定返回 0，不抛错");
    }

    @Test
    @DisplayName("幂等与稳定结果：重复下线同一条会话返回 true；不存在会话恒返回 false")
    void revokeIsIdempotentAndStable() {
        TokenPair p = authService.login("alice", "alice123");
        String id = authService.authenticateAccessToken(p.accessToken()).sessionId();

        assertTrue(adminService.revokeSession(id));
        assertTrue(adminService.revokeSession(id), "已撤销会话再次下线仍稳定返回 true");
        for (int i = 0; i < 5; i++) {
            assertFalse(adminService.revokeSession("sess-does-not-exist-" + i),
                    "不存在会话稳定返回 false，不抛底层错误");
        }
        for (int i = 0; i < 3; i++) {
            assertReason(AuthFailureReason.SESSION_REVOKED,
                    () -> authService.authenticateAccessToken(p.accessToken()));
        }
    }

    @Test
    @DisplayName("并发：刷新换发与强制下线同时发生，撤销必定最终生效，新令牌不会救活会话")
    void concurrentRefreshVsRevokeNeverResurrects() throws Exception {
        int iterations = 30;
        for (int round = 0; round < iterations; round++) {
            TokenPair pair = authService.login("alice", "alice123");
            String sessionId = authService.authenticateAccessToken(pair.accessToken()).sessionId();

            ConcurrentLinkedQueue<TokenPair> winners = new ConcurrentLinkedQueue<>();
            ConcurrentLinkedQueue<AuthFailureReason> failures = new ConcurrentLinkedQueue<>();
            AtomicInteger errors = new AtomicInteger();
            runRaceRound(pair, sessionId, winners, failures, errors);

            assertEquals(0, errors.get(), "第 " + round + " 轮出现非预期异常");
            // 无论刷新与撤销谁先谁后：原访问令牌必失效
            assertReason(AuthFailureReason.SESSION_REVOKED,
                    () -> authService.authenticateAccessToken(pair.accessToken()));
            // 抢到刷新的线程拿到的新令牌对，也必须随会话撤销立即失效
            for (TokenPair winner : winners) {
                assertReason(AuthFailureReason.SESSION_REVOKED,
                        () -> authService.authenticateAccessToken(winner.accessToken()));
                assertReason(AuthFailureReason.SESSION_REVOKED,
                        () -> authService.refresh(winner.refreshToken()));
            }
            // 刷新失败只允许是 CAS 落败（REUSED）或撤销先到（REVOKED）
            for (AuthFailureReason reason : failures) {
                assertTrue(reason == AuthFailureReason.REFRESH_TOKEN_REUSED
                                || reason == AuthFailureReason.SESSION_REVOKED,
                        "不允许出现其他失败原因: " + reason);
            }
        }
        AuthTestLogger.result(log, "完成 {} 轮刷新/撤销竞争，撤销全部最终生效，无一例救活", iterations);
    }

    @Test
    @DisplayName("并发：撤销进行中多个旧访问令牌请求，结论只可能是成功或已撤销，撤销后一律拒绝")
    void concurrentAccessDuringRevoke() throws Exception {
        TokenPair pair = authService.login("alice", "alice123");
        String sessionId = authService.authenticateAccessToken(pair.accessToken()).sessionId();
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch ready = new CountDownLatch(threads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger revoked = new AtomicInteger();
        AtomicInteger weird = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    authService.authenticateAccessToken(pair.accessToken());
                    allowed.incrementAndGet();
                } catch (AuthException ex) {
                    if (ex.reason() == AuthFailureReason.SESSION_REVOKED) {
                        revoked.incrementAndGet();
                    } else {
                        weird.incrementAndGet();
                    }
                }
                return null;
            });
        }
        Future<?> revoker = pool.submit(() -> {
            ready.countDown();
            try {
                start.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            adminService.revokeSession(sessionId);
            return null;
        });
        ready.await();
        start.countDown();
        revoker.get();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

        assertEquals(0, weird.get(), "撤销期间访问结论不允许出现撤销以外的错误分类");
        assertEquals(threads, allowed.get() + revoked.get());
        assertReason(AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(pair.accessToken()));
        AuthTestLogger.result(log, "竞争期放行={} 拒绝={}，撤销后再访问一律 SESSION_REVOKED",
                allowed.get(), revoked.get());
    }

    /** 单轮竞争：多线程在同一闭锁后同时刷新（3 个）/撤销（3 个）。 */
    private void runRaceRound(TokenPair pair, String sessionId,
                              ConcurrentLinkedQueue<TokenPair> winners,
                              ConcurrentLinkedQueue<AuthFailureReason> failures,
                              AtomicInteger errors) throws Exception {
        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            final boolean refresher = t % 2 == 0;
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    if (refresher) {
                        winners.add(authService.refresh(pair.refreshToken()));
                    } else {
                        adminService.revokeSession(sessionId);
                    }
                } catch (AuthException ex) {
                    failures.add(ex.reason());
                } catch (RuntimeException ex) {
                    errors.incrementAndGet();
                }
                return null;
            });
        }
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
    }

    private static void assertReason(AuthFailureReason expected, Runnable action) {
        try {
            action.run();
            throw new AssertionError("期望失败 " + expected + " 但调用成功");
        } catch (AuthException ex) {
            assertEquals(expected, ex.reason(), "期望 " + expected + " 实际 " + ex.reason());
        }
    }
}
