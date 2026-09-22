package com.github.h3yow.revocablesessionauthjava.tests;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.domain.TokenPair;
import com.github.h3yow.revocablesessionauthjava.security.AuthService;
import com.github.h3yow.revocablesessionauthjava.security.session.SessionStore;
import com.github.h3yow.revocablesessionauthjava.security.token.TokenService;
import com.github.h3yow.revocablesessionauthjava.security.user.UserStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 刷新令牌轮换语义测试。
 */
class RefreshRotationTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshRotationTest.class);

    private static final long T0 = 2_000_000_000L;
    private Clock clock;
    private TokenService tokenService;
    private SessionStore sessionStore;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.ofEpochSecond(T0), ZoneOffset.UTC);
        tokenService = new TokenService(clock, "refresh-rotation-test-secret-0123456789", 300, 3600);
        sessionStore = new SessionStore();
        authService = new AuthService(tokenService, sessionStore, new UserStore());
    }

    private void expectError(String caseName, String input, TokenError expected, String basis) {
        AuthException ex = assertThrows(AuthException.class, () -> authService.refresh(input), caseName);
        log.info("用例={} 输入={} 判定依据={} 结果={}", caseName, abbreviate(input), basis, ex.error().name());
        assertEquals(expected, ex.error(), caseName);
    }

    @Test
    void rotationIssuesNewPairAndInvalidatesOldRefreshToken() {
        TokenPair login = authService.login("alice", "user123");
        log.info("用例=轮换-登录 输入=alice/user123 判定依据=密码校验通过并建立会话 结果=获得令牌对");

        TokenPair rotated = authService.refresh(login.refreshToken());
        log.info("用例=轮换-首次刷新 输入=登录签发的刷新令牌 判定依据=jti与会话当前jti匹配，原子写为新jti 结果=accessChanged={},refreshChanged={}",
                !rotated.accessToken().equals(login.accessToken()),
                !rotated.refreshToken().equals(login.refreshToken()));
        assertNotEquals(login.refreshToken(), rotated.refreshToken(), "必须轮换出新的刷新令牌");
        assertNotEquals(login.accessToken(), rotated.accessToken());

        // 旧刷新令牌立即失效：按重放处理并连带撤销会话族
        expectError("旧刷新令牌被再次使用", login.refreshToken(), TokenError.REUSE_DETECTED,
                "会话当前jti已不等于旧令牌jti，判定为重放，撤销整个会话族");

        // 会话族已被撤销：新签发的刷新令牌同样无法再换发
        expectError("族撤销后新刷新令牌被拒绝", rotated.refreshToken(), TokenError.REUSE_DETECTED,
                "重放已把会话标记为撤销（原因为REUSE_DETECTED），后续刷新一律拒绝");
    }

    @Test
    void refreshAfterLogoutIsRejected() {
        TokenPair login = authService.login("alice", "user123");
        authService.logout(login.refreshToken());
        log.info("用例=注销后刷新 输入=注销 判定依据=会话revoked=true 结果=准备验证刷新被拒");
        expectError("注销后使用刷新令牌", login.refreshToken(), TokenError.REVOKED_SESSION,
                "会话已主动撤销，拒绝换发");
    }

    @Test
    void expiredRefreshTokenIsRejected() {
        TokenPair login = authService.login("alice", "user123");
        clock = Clock.fixed(Instant.ofEpochSecond(T0 + 3601), ZoneOffset.UTC);
        tokenService = new TokenService(clock, "refresh-rotation-test-secret-0123456789", 300, 3600);
        authService = new AuthService(tokenService, sessionStore, new UserStore());
        expectError("刷新令牌过期", login.refreshToken(), TokenError.EXPIRED_TOKEN,
                "当前时间超过刷新令牌 exp（TTL 3600s）");
    }

    @Test
    void accessTokenCannotBeUsedAsRefreshToken() {
        TokenPair login = authService.login("alice", "user123");
        expectError("拿访问令牌刷新", login.accessToken(), TokenError.UNSUPPORTED_TOKEN,
                "验签通过但 typ=AT，刷新端点只接受 RT");
    }

    @Test
    void badLoginCredentialsAreRejected() {
        AuthException ex = assertThrows(AuthException.class,
                () -> authService.login("alice", "wrong-password"));
        log.info("用例=错误密码登录 输入=alice/wrong-password 判定依据=盐摘要不匹配 结果={}", ex.error().name());
        assertEquals(TokenError.BAD_CREDENTIALS, ex.error());

        AuthException ex2 = assertThrows(AuthException.class,
                () -> authService.login("nobody", "whatever"));
        log.info("用例=未知用户登录 输入=nobody 判定依据=用户不存在，与密码错误统一归类 结果={}", ex2.error().name());
        assertEquals(TokenError.BAD_CREDENTIALS, ex2.error());
    }

    @Test
    void doubleRefreshTwiceBothFailAfterSingleSuccess() {
        TokenPair login = authService.login("alice", "user123");
        TokenPair rotated = authService.refresh(login.refreshToken());
        // 同一旧令牌的第三次、第四次使用同样必须被拒绝，结论保持可解释
        expectError("旧令牌第三次使用", login.refreshToken(), TokenError.REUSE_DETECTED, "幂等重放仍撤销");
        expectError("旧令牌第四次使用", login.refreshToken(), TokenError.REUSE_DETECTED, "幂等重放仍撤销");
        assertTrue(rotated.accessToken().startsWith("eyJ"));
    }

    private static String abbreviate(String token) {
        if (token == null) {
            return "null";
        }
        return token.length() > 24 ? token.substring(0, 24) + "...(" + token.length() + "chars)" : token;
    }
}
