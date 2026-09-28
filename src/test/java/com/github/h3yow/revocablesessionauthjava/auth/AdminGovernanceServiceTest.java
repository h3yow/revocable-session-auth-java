package com.github.h3yow.revocablesessionauthjava.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.revocablesessionauthjava.support.AuthAssertions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;

/**
 * 管理员会话治理的领域测试：强制下线即时失效、同用户其他会话不受牵连、
 * 操作幂等可重复、撤销与并发刷新不抢时序（会话不可能被救活）。
 */
@SpringBootTest
@Import(TestClockConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AdminGovernanceServiceTest {

    private static final Logger log = AuthTestLogger.logger(AdminGovernanceServiceTest.class);

    @Autowired
    private AuthService authService;

    @Test
    @DisplayName("强制下线单条会话：旧访问令牌与刷新令牌立即失效")
    void revokeOneSessionKillsItsTokensImmediately() {
        TokenPair pair = authService.login("alice", "alice123");
        Authentication auth = authService.authenticateAccessToken(pair.accessToken());
        String sessionId = auth.sessionId();
        AuthTestLogger.input(log, "alice 会话 sessionId={} 正常使用中，管理员强制下线", sessionId);

        SessionRevocationResult result = authService.revokeSession(sessionId);
        AuthTestLogger.basis(log, "会话锁内置 revoked=true，访问令牌实时回查立即生效");
        assertTrue(result.found());
        assertTrue(result.revoked());
        assertFalse(result.alreadyRevoked());

        AuthTestLogger.result(log, "旧 accessToken 下一次请求即 SESSION_REVOKED");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(pair.accessToken()));
        AuthTestLogger.result(log, "旧 refreshToken 换新即 SESSION_REVOKED");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.refresh(pair.refreshToken()));
    }

    @Test
    @DisplayName("同一用户其他会话不受牵连")
    void revokeOneSessionDoesNotAffectSiblings() {
        TokenPair deviceA = authService.login("alice", "alice123");
        TokenPair deviceB = authService.login("alice", "alice123");
        String sessionA = authService.authenticateAccessToken(deviceA.accessToken()).sessionId();
        AuthTestLogger.input(log, "alice 有两条会话 A={} B，强制下线 A", sessionA);

        authService.revokeSession(sessionA);
        AuthTestLogger.basis(log, "撤销只置位目标会话，不触碰同用户其他会话");

        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(deviceA.accessToken()));
        Authentication stillValid = authService.authenticateAccessToken(deviceB.accessToken());
        TokenPair rotatedB = authService.refresh(deviceB.refreshToken());
        authService.authenticateAccessToken(rotatedB.accessToken());
        AuthTestLogger.result(log, "会话 B 访问与刷新均 SUCCESS username={}", stillValid.username());
        assertEquals("alice", stillValid.username());

        SessionOverviewResponse overview = authService.listActiveSessions("alice");
        assertEquals(1, overview.activeSessionCount(), "概览中只剩 B 一条生效会话");
    }

    @Test
    @DisplayName("强制下线用户全部会话；不存在会话与重复操作结果稳定可重复")
    void revokeAllAndIdempotency() {
        TokenPair p1 = authService.login("alice", "alice123");
        TokenPair p2 = authService.login("alice", "alice123");
        String session1 = authService.authenticateAccessToken(p1.accessToken()).sessionId();
        String session2 = authService.authenticateAccessToken(p2.accessToken()).sessionId();
        SessionOverviewResponse before = authService.listActiveSessions("alice");
        AuthTestLogger.input(log, "alice 生效会话数={}，批量强制下线", before.activeSessionCount());
        assertEquals(2, before.activeSessionCount());

        UserRevocationResult result = authService.revokeUserSessions("alice");
        AuthTestLogger.basis(log, "逐条会话锁内置撤销位");
        assertEquals(2, result.revokedSessionCount());
        assertEquals(2, result.sessionIds().size());

        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(p1.accessToken()));
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(p2.accessToken()));

        AuthTestLogger.input(log, "重复批量强制下线（幂等）");
        UserRevocationResult again = authService.revokeUserSessions("alice");
        assertEquals(0, again.revokedSessionCount(), "已撤销会话不再计入，结果稳定");
        assertEquals(0, authService.listActiveSessions("alice").activeSessionCount());

        AuthTestLogger.input(log, "对不存在的会话强制下线");
        SessionRevocationResult missing = authService.revokeSession("sess-does-not-exist");
        AuthTestLogger.result(log, "found={} revoked={}，不抛底层错误", missing.found(), missing.revoked());
        assertFalse(missing.found());
        assertFalse(missing.revoked());

        AuthTestLogger.input(log, "对已撤销会话重复单条强制下线");
        SessionRevocationResult duplicate = authService.revokeSession(session1);
        assertTrue(duplicate.found());
        assertTrue(duplicate.revoked());
        assertTrue(duplicate.alreadyRevoked(), "重复强制下线稳定标记 alreadyRevoked");
        // 另一条同样幂等，且不影响结论
        SessionRevocationResult duplicate2 = authService.revokeSession(session2);
        assertTrue(duplicate2.found());
        assertTrue(duplicate2.alreadyRevoked());

        AuthTestLogger.input(log, "治理不存在的用户");
        AuthAssertions.assertFailure(log, AuthFailureReason.USER_NOT_FOUND,
                () -> authService.listActiveSessions("ghost"));
        AuthAssertions.assertFailure(log, AuthFailureReason.USER_NOT_FOUND,
                () -> authService.revokeUserSessions("ghost"));
    }

    @Test
    @DisplayName("并发：撤销与刷新竞争，撤销必然生效，会话不可能被刷新救活")
    void revokeRacingWithRefreshCannotReviveSession() throws Exception {
        int rounds = 30;
        int leaked = 0;
        for (int round = 0; round < rounds; round++) {
            TokenPair pair = authService.login("alice", "alice123");
            String sessionId = authService.authenticateAccessToken(pair.accessToken()).sessionId();

            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            AtomicReference<TokenPair> refreshOutcome = new AtomicReference<>();
            AtomicReference<AuthFailureReason> refreshFailure = new AtomicReference<>();
            List<Future<?>> futures = new ArrayList<>();

            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                try {
                    refreshOutcome.set(authService.refresh(pair.refreshToken()));
                } catch (AuthException ex) {
                    refreshFailure.set(ex.reason());
                }
                return null;
            }));
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                authService.revokeSession(sessionId);
                return null;
            }));
            ready.await();
            start.countDown();
            for (Future<?> f : futures) {
                f.get();
            }
            pool.shutdown();

            // 无论谁先谁后：最终所有访问令牌（旧的 + 可能轮换出的新的）都必须立刻不可用
            boolean oldAccessUsable = isUsable(pair.accessToken());
            boolean newAccessUsable = refreshOutcome.get() != null
                    && isUsable(refreshOutcome.get().accessToken());
            if (oldAccessUsable || newAccessUsable) {
                leaked++;
            }
            if (refreshFailure.get() != null) {
                assertEquals(AuthFailureReason.SESSION_REVOKED, refreshFailure.get(),
                        "刷新失败时只可能是会话已撤销，不能是其他竞争错误");
            }
        }
        AuthTestLogger.basis(log, "刷新临界区与撤销在同一把会话锁上串行，共 {} 轮", rounds);
        AuthTestLogger.result(log, "出现“撤销后令牌仍可用”的轮次={}", leaked);
        assertEquals(0, leaked, "任何一轮都不允许撤销后仍有可用令牌（会话被救活）");
    }

    @Test
    @DisplayName("角色 Web 化调整后：旧访问令牌按新权限判定，刷新/重登按新角色生效")
    void roleChangeViaServiceAppliesToOldTokens() {
        TokenPair pair = authService.login("alice", "alice123");
        Authentication before = authService.authenticateAccessToken(pair.accessToken());
        assertTrue(Permissions.satisfies(before.permissions(), new String[]{"profile:read"}));
        assertFalse(Permissions.satisfies(before.permissions(), new String[]{"admin:stats"}));

        int affected = authService.changeRoles("alice", java.util.Set.of(Permissions.ROLE_ADMIN));
        AuthTestLogger.basis(log, "{} 个会话版本提升，旧令牌版本不符", affected);
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_STATE_CHANGED,
                () -> authService.authenticateAccessToken(pair.accessToken()));

        TokenPair refreshed = authService.refresh(pair.refreshToken());
        Set<String> refreshedPermissions =
                authService.authenticateAccessToken(refreshed.accessToken()).permissions();
        AuthTestLogger.result(log, "刷新后 permissions={} 命中 admin:stats", refreshedPermissions);
        assertTrue(Permissions.satisfies(refreshedPermissions, new String[]{"admin:stats"}));

        // 重新登录同样按新角色（目录已落盘）
        TokenPair relogin = authService.login("alice", "alice123");
        assertTrue(authService.authenticateAccessToken(relogin.accessToken())
                .permissions().contains(Permissions.WILDCARD));

        AuthAssertions.assertFailure(log, AuthFailureReason.USER_NOT_FOUND,
                () -> authService.changeRoles("ghost", Set.of(Permissions.ROLE_USER)));
    }

    private boolean isUsable(String accessToken) {
        try {
            authService.authenticateAccessToken(accessToken);
            return true;
        } catch (AuthException ex) {
            return false;
        }
    }
}
