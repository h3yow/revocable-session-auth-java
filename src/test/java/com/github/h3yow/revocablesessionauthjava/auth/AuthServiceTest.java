package com.github.h3yow.revocablesessionauthjava.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.revocablesessionauthjava.support.AuthAssertions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.MutableClock;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import com.github.h3yow.revocablesessionauthjava.token.TokenService;
import java.time.Duration;
import java.util.List;
import java.util.Set;
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
 * 认证服务领域测试：登录、刷新轮换、并发单次成功、撤销即时生效、
 * 权限变更后旧令牌失效、未知/过期刷新令牌分类。
 */
@SpringBootTest
@Import(TestClockConfig.class)
class AuthServiceTest {

    private static final Logger log = AuthTestLogger.logger(AuthServiceTest.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private MutableClock clock;

    @Test
    @DisplayName("登录：正确凭据成功；错误密码/未知用户 -> BAD_CREDENTIALS")
    void loginOutcomes() {
        AuthTestLogger.input(log, "username=alice password=alice123");
        TokenPair pair = authService.login("alice", "alice123");
        AuthTestLogger.basis(log, "用户目录命中且密码相等");
        AuthTestLogger.result(log, "SUCCESS 签发 accessToken/refreshToken，accessTtl={}s",
                pair.accessTokenExpiresInSeconds());
        assertTrue(pair.accessToken().contains("."));

        AuthTestLogger.input(log, "username=alice password=wrong");
        AuthTestLogger.basis(log, "密码不匹配 -> 统一 BAD_CREDENTIALS，不提示用户是否存在");
        AuthAssertions.assertFailure(log, AuthFailureReason.BAD_CREDENTIALS,
                () -> authService.login("alice", "wrong"));

        AuthTestLogger.input(log, "username=ghost password=x（不存在）");
        AuthAssertions.assertFailure(log, AuthFailureReason.BAD_CREDENTIALS,
                () -> authService.login("ghost", "x"));
    }

    @Test
    @DisplayName("刷新轮换：新令牌签发，旧刷新令牌立即失效（重用被拒）")
    void rotationInvalidatesOldRefreshToken() {
        TokenPair first = authService.login("alice", "alice123");
        AuthTestLogger.input(log, "首次登录获得 refreshToken={}", abbreviate(first.refreshToken()));

        TokenPair second = authService.refresh(first.refreshToken());
        AuthTestLogger.basis(log, "旧令牌有效且 CAS 抢占成功，签发全新 jti 的令牌对");
        AuthTestLogger.result(log, "SUCCESS accessChanged={} refreshChanged={}",
                !second.accessToken().equals(first.accessToken()),
                !second.refreshToken().equals(first.refreshToken()));
        assertNotEquals(first.refreshToken(), second.refreshToken());
        assertNotEquals(first.accessToken(), second.accessToken());

        AuthTestLogger.input(log, "再次使用旧 refreshToken={}", abbreviate(first.refreshToken()));
        AuthTestLogger.basis(log, "旧令牌服务端记录 used=true，CAS(false->true) 失败");
        AuthAssertions.assertFailure(log, AuthFailureReason.REFRESH_TOKEN_REUSED,
                () -> authService.refresh(first.refreshToken()));

        // 新刷新令牌仍可正常使用，且轮换链继续有效
        TokenPair third = authService.refresh(second.refreshToken());
        AuthTestLogger.result(log, "轮换后新令牌可用 SUCCESS session 连续，新 access={}",
                abbreviate(third.accessToken()));
    }

    @Test
    @DisplayName("并发刷新：同一刷新令牌只有一个请求成功，其余明确拒绝")
    void concurrentRefreshOnlyOneSucceeds() throws Exception {
        TokenPair pair = authService.login("alice", "alice123");
        int threads = 8;
        AuthTestLogger.input(log, "同一 refreshToken 并发线程数={}", threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger reused = new AtomicInteger();
        List<Future<?>> futures = new java.util.ArrayList<>();

        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                try {
                    authService.refresh(pair.refreshToken());
                    success.incrementAndGet();
                } catch (AuthException ex) {
                    if (ex.reason() == AuthFailureReason.REFRESH_TOKEN_REUSED) {
                        reused.incrementAndGet();
                    } else {
                        throw ex;
                    }
                }
                return null;
            }));
        }
        ready.await();
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        AuthTestLogger.basis(log, "CAS 抢占保证 used 标志只能被翻转一次");
        AuthTestLogger.result(log, "success={} reused={} 其余失败原因总数={}",
                success.get(), reused.get(), threads);
        assertEquals(1, success.get(), "必须恰好一次刷新成功");
        assertEquals(threads - 1, reused.get(), "其余请求必须全部被明确拒绝为 REUSED");
    }

    @Test
    @DisplayName("注销后：会话撤销，旧访问令牌被拒（SESSION_REVOKED），刷新同样被拒")
    void logoutRevokesAccessImmediately() {
        TokenPair pair = authService.login("alice", "alice123");
        Authentication auth = authService.authenticateAccessToken(pair.accessToken());
        AuthTestLogger.basis(log, "注销前访问令牌校验通过 username={}", auth.username());

        authService.logout(pair.refreshToken());
        AuthTestLogger.input(log, "已注销 sessionId={}，继续使用同一 accessToken", auth.sessionId());
        AuthTestLogger.basis(log, "每次访问实时回查会话，revoked=true 立即生效，无缓存窗口");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.authenticateAccessToken(pair.accessToken()));

        AuthTestLogger.input(log, "注销后尝试用 refreshToken 换新");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_REVOKED,
                () -> authService.refresh(pair.refreshToken()));
    }

    @Test
    @DisplayName("权限变更：旧访问令牌按 SESSION_STATE_CHANGED 拒绝；重新登录后按新角色生效")
    void roleChangeInvalidatesOldAccessTokens() {
        TokenPair pair = authService.login("alice", "alice123");
        Authentication before = authService.authenticateAccessToken(pair.accessToken());
        AuthTestLogger.basis(log, "变更前 permissions={}", before.permissions());
        assertTrue(before.permissions().contains(Permissions.PROFILE_READ));
        assertFalse(before.permissions().contains(Permissions.ADMIN_STATS));

        authService.changeRoles("alice", Set.of(Permissions.ROLE_ADMIN));
        AuthTestLogger.input(log, "管理员把 alice 角色变更为 ROLE_ADMIN，再用旧 accessToken");
        AuthTestLogger.basis(log, "会话 version 提升，旧令牌携带版本与会话版本不一致");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_STATE_CHANGED,
                () -> authService.authenticateAccessToken(pair.accessToken()));

        TokenPair refreshed = authService.refresh(pair.refreshToken());
        AuthTestLogger.result(log, "重新获得令牌后按最新角色判定 permissions={}",
                authService.authenticateAccessToken(refreshed.accessToken()).permissions());
        assertTrue(authService.authenticateAccessToken(refreshed.accessToken())
                .permissions().contains(Permissions.WILDCARD));
    }

    @Test
    @DisplayName("未知/过期/类型错误的刷新令牌分别归类")
    void refreshTokenFailureCategories() {
        TokenPair pair = authService.login("alice", "alice123");

        AuthTestLogger.input(log, "用 accessToken 调刷新接口");
        AuthTestLogger.basis(log, "令牌类型与场景不符");
        AuthAssertions.assertFailure(log, AuthFailureReason.WRONG_TOKEN_TYPE,
                () -> authService.refresh(pair.accessToken()));

        clock.advance(Duration.ofSeconds(3601));
        AuthTestLogger.input(log, "推进时钟 3601s 后用 refreshToken 刷新");
        AuthTestLogger.basis(log, "先做无状态过期判定");
        AuthAssertions.assertFailure(log, AuthFailureReason.EXPIRED,
                () -> authService.refresh(pair.refreshToken()));
    }

    @Test
    @DisplayName("结构不合法或内容篡改的访问令牌：MALFORMED / TAMPERED_TOKEN")
    void malformedAndTamperedAccessTokens() {
        TokenPair pair = authService.login("alice", "alice123");
        AuthTestLogger.input(log, "访问令牌='garbage' 与篡改串");
        AuthAssertions.assertFailure(log, AuthFailureReason.MALFORMED_TOKEN,
                () -> authService.authenticateAccessToken("garbage"));
        String tampered = "x" + pair.accessToken().substring(1);
        AuthTestLogger.basis(log, "payload 翻转一个字符，签名形态合法但重算 HMAC 不一致 -> TAMPERED_TOKEN");
        AuthAssertions.assertFailure(log, AuthFailureReason.TAMPERED_TOKEN,
                () -> authService.authenticateAccessToken(tampered));
    }

    @Test
    @DisplayName("令牌与服务端登记对不上：无会话/无刷新令牌登记 -> SESSION_TOKEN_MISMATCH")
    void tokenNotMatchingServerRegistration() {
        AuthTestLogger.input(log, "用本服务密钥签发指向不存在会话的访问令牌与刷新令牌");
        com.github.h3yow.revocablesessionauthjava.token.TokenClaims ghostAccess =
                tokenService.issue("sess-ghost", "alice", 0, TokenType.ACCESS);
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_TOKEN_MISMATCH,
                () -> authService.authenticateAccessToken(tokenService.sign(ghostAccess)));

        com.github.h3yow.revocablesessionauthjava.token.TokenClaims ghostRefresh =
                tokenService.issue("sess-ghost", "alice", 0, TokenType.REFRESH);
        AuthTestLogger.basis(log, "刷新令牌签名合法但服务端无 jti 登记");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_TOKEN_MISMATCH,
                () -> authService.refresh(tokenService.sign(ghostRefresh)));
        AuthTestLogger.result(log, "无登记场景与登记对不上场景统一稳定落 SESSION_TOKEN_MISMATCH");
    }

    private static String abbreviate(String token) {
        return token == null ? "<null>" : token.substring(0, Math.min(20, token.length())) + "...";
    }
}
