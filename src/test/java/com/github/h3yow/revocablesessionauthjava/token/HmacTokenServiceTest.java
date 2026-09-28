package com.github.h3yow.revocablesessionauthjava.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import com.github.h3yow.revocablesessionauthjava.auth.TokenType;
import com.github.h3yow.revocablesessionauthjava.support.AuthAssertions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.MutableClock;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

/**
 * 令牌签发与校验的失败分类测试：
 * 正常签发/校验、内容篡改、伪造签名、类型不符、过期、格式错误、缺失。
 */
class HmacTokenServiceTest {

    private static final Logger log = AuthTestLogger.logger(HmacTokenServiceTest.class);

    private MutableClock clock;
    private HmacTokenService tokenService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        tokenService = new HmacTokenService(clock, "unit-test-secret-0123456789", 300, 3600);
    }

    @Test
    @DisplayName("正常令牌：签发后可校验，声明一致")
    void issueAndVerifyRoundTrip() {
        AuthTestLogger.input(log, "sessionId=sess-1 username=alice version=0 type=ACCESS");
        TokenClaims claims = tokenService.issue("sess-1", "alice", 0, TokenType.ACCESS);
        String compact = tokenService.sign(claims);
        AuthTestLogger.basis(log, "未篡改、未过期、类型匹配，HMAC 签名一致");
        TokenClaims parsed = tokenService.parseAndVerify(compact, TokenType.ACCESS);
        assertEquals("sess-1", parsed.sessionId());
        assertEquals("alice", parsed.username());
        assertEquals(TokenType.ACCESS, parsed.type());
        AuthTestLogger.result(log, "SUCCESS claims={} token={}", parsed, abbreviate(compact));
    }

    @Test
    @DisplayName("内容被篡改：payload 改动但签名形态合法 -> TAMPERED_TOKEN")
    void tamperedPayloadRejected() {
        TokenClaims claims = tokenService.issue("sess-1", "alice", 0, TokenType.ACCESS);
        String compact = tokenService.sign(claims);
        String tampered = flipPayloadCharacter(compact);
        AuthTestLogger.input(log, "原始={} 篡改后={}", abbreviate(compact), abbreviate(tampered));
        AuthTestLogger.basis(log, "签名段形态合法但与 payload 重算的 HMAC 不一致 -> TAMPERED_TOKEN");
        AuthAssertions.assertFailure(log, AuthFailureReason.TAMPERED_TOKEN,
                () -> tokenService.parseAndVerify(tampered, TokenType.ACCESS));
    }

    @Test
    @DisplayName("伪造签名：长度不符的随机签名段 -> INVALID_SIGNATURE")
    void forgedSignatureRejected() {
        TokenClaims claims = tokenService.issue("sess-1", "alice", 0, TokenType.ACCESS);
        String compact = tokenService.sign(claims);
        String forged = compact.substring(0, compact.lastIndexOf('.') + 1) + "AAAAAAAAAAAAAAAAAAAA";
        AuthTestLogger.input(log, "合法 payload + 攻击者伪造的短签名段（解码 15 字节）");
        AuthTestLogger.basis(log, "签名段连 HMAC-SHA256 的 32 字节输出形态都不具备 -> INVALID_SIGNATURE");
        AuthAssertions.assertFailure(log, AuthFailureReason.INVALID_SIGNATURE,
                () -> tokenService.parseAndVerify(forged, TokenType.ACCESS));
    }

    @Test
    @DisplayName("类型混用：拿刷新令牌走访问校验 -> WRONG_TOKEN_TYPE")
    void wrongTypeRejected() {
        TokenClaims refresh = tokenService.issue("sess-1", "alice", 0, TokenType.REFRESH);
        String compact = tokenService.sign(refresh);
        AuthTestLogger.input(log, "type=REFRESH 的令牌，期望按 ACCESS 校验");
        AuthTestLogger.basis(log, "签名/有效期均合法，但声明类型与使用场景不符");
        AuthAssertions.assertFailure(log, AuthFailureReason.WRONG_TOKEN_TYPE,
                () -> tokenService.parseAndVerify(compact, TokenType.ACCESS));
    }

    @Test
    @DisplayName("访问令牌过期 -> EXPIRED")
    void expiredAccessTokenRejected() {
        TokenClaims claims = tokenService.issue("sess-1", "alice", 0, TokenType.ACCESS);
        String compact = tokenService.sign(claims);
        clock.advance(Duration.ofSeconds(301));
        AuthTestLogger.input(log, "推进时钟 301s（访问令牌 TTL=300s）");
        AuthTestLogger.basis(log, "expiresAt <= 当前时间");
        AuthAssertions.assertFailure(log, AuthFailureReason.EXPIRED,
                () -> tokenService.parseAndVerify(compact, TokenType.ACCESS));
    }

    @Test
    @DisplayName("刷新令牌过期 -> EXPIRED")
    void expiredRefreshTokenRejected() {
        TokenClaims claims = tokenService.issue("sess-1", "alice", 0, TokenType.REFRESH);
        String compact = tokenService.sign(claims);
        clock.advance(Duration.ofSeconds(3601));
        AuthTestLogger.input(log, "推进时钟 3601s（刷新令牌 TTL=3600s）");
        AuthAssertions.assertFailure(log, AuthFailureReason.EXPIRED,
                () -> tokenService.parseAndVerify(compact, TokenType.REFRESH));
    }

    @Test
    @DisplayName("格式错误：非两段/非法 base64url -> MALFORMED_TOKEN")
    void malformedTokensRejected() {
        AuthTestLogger.input(log, "候选令牌分别为 'not-a-token'、'a.b.c'、'.'、空串");
        AuthTestLogger.basis(log, "不满足 payload.signature 两段结构或 base64url 不可解码");
        AuthAssertions.assertFailure(log, AuthFailureReason.MALFORMED_TOKEN,
                () -> tokenService.parseAndVerify("not-a-token", TokenType.ACCESS));
        AuthAssertions.assertFailure(log, AuthFailureReason.MALFORMED_TOKEN,
                () -> tokenService.parseAndVerify("a.b.c", TokenType.ACCESS));
        AuthAssertions.assertFailure(log, AuthFailureReason.MALFORMED_TOKEN,
                () -> tokenService.parseAndVerify(".", TokenType.ACCESS));
        AuthAssertions.assertFailure(log, AuthFailureReason.MISSING_TOKEN,
                () -> tokenService.parseAndVerify("   ", TokenType.ACCESS));
        AuthTestLogger.result(log, "全部按预期分类为 MALFORMED_TOKEN / MISSING_TOKEN");
    }

    @Test
    @DisplayName("跨密钥签发：外形合法但服务端密钥重算不一致 -> TAMPERED_TOKEN")
    void differentSecretRejected() {
        HmacTokenService attacker = new HmacTokenService(clock, "attacker-secret-999999", 300, 3600);
        String forged = attacker.sign(attacker.issue("sess-1", "alice", 0, TokenType.ACCESS));
        AuthTestLogger.input(log, "攻击者用独立密钥签发外形完全合法的令牌");
        AuthTestLogger.basis(log, "签名形态合法但与本服务密钥重算值不一致，对校验端等同内容被改动 -> TAMPERED_TOKEN");
        AuthAssertions.assertFailure(log, AuthFailureReason.TAMPERED_TOKEN,
                () -> tokenService.parseAndVerify(forged, TokenType.ACCESS));
    }


    /** 将 payload 段首字符做 base64url 安全的翻转，模拟内容被篡改。 */
    private static String flipPayloadCharacter(String compact) {
        int dot = compact.indexOf('.');
        char first = compact.charAt(0);
        char flipped = first == 'A' ? 'B' : 'A';
        return flipped + compact.substring(1, dot) + compact.substring(dot);
    }

    private static String abbreviate(String token) {
        return token == null ? "<null>" : token.substring(0, Math.min(24, token.length())) + "...";
    }
}
