package com.github.h3yow.revocablesessionauthjava.tests;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.security.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 令牌验签失败分类测试：缺失 / 伪造结构 / 内容篡改 / 签名不匹配 / 过期 / 类型错误。
 * 每条用例打印 输入、判定依据、结果。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);
    private static final String SECRET = "unit-test-hmac-secret-0123456789abcdef";

    private TokenService tokenServiceAt(long epochSecond) {
        return new TokenService(Clock.fixed(Instant.ofEpochSecond(epochSecond), ZoneOffset.UTC),
                SECRET, 300, 1209600);
    }

    private void assertError(String caseName, String input, TokenService service,
                             TokenError expected, String basis) {
        AuthException ex = assertThrows(AuthException.class, () -> service.verify(input));
        log.info("用例={} 输入={} 判定依据={} 结果={}", caseName, input, basis, ex.error().name());
        assertEquals(expected, ex.error(), caseName);
    }

    @Test
    void missingTokenIsRejected() {
        TokenService svc = tokenServiceAt(1_000_000);
        AuthException nullEx = assertThrows(AuthException.class, () -> svc.verify(null));
        log.info("用例=令牌缺失 输入=null 判定依据=verify 收到 null 结果={}", nullEx.error().name());
        assertEquals(TokenError.MISSING_TOKEN, nullEx.error());
        // 空白输入（仅空格）应判为缺失而非伪造
        AuthException blankEx = assertThrows(AuthException.class, () -> svc.verify("   "));
        log.info("用例=令牌空白 输入=(三个空格) 判定依据=isBlank() 命中 结果={}", blankEx.error().name());
        assertEquals(TokenError.MISSING_TOKEN, blankEx.error());
    }

    @Test
    void forgedStructureIsRejected() {
        TokenService svc = tokenServiceAt(1_000_000);
        assertError("非三段式", "not-a-jwt-like-value", svc, TokenError.FORGED_TOKEN,
                "令牌不是 header.payload.signature 三段结构");
        assertError("Base64不合法", "%%%.!!!.@@@", svc, TokenError.FORGED_TOKEN,
                "任一片段不是合法 base64url");
        // 头部解码后不是 JSON / alg 不为 HS256，同样视为伪造
        String badHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"typ\":\"AT\",\"sub\":\"u\",\"sid\":\"s\",\"jti\":\"j\",\"iat\":1,\"exp\":2}".getBytes());
        assertError("头部alg不被认可", badHeader + "." + payload + "." + payload, svc,
                TokenError.FORGED_TOKEN, "头部可解码但 alg 不是受支持的 HS256");
    }

    @Test
    void tamperedPayloadIsRejected() {
        TokenService svc = tokenServiceAt(1_000_000);
        String valid = svc.issueAccessToken("u-1", "s-1", "jti-1");
        String header = valid.split("\\.")[0];
        String signature = valid.split("\\.")[2];
        // 合法 base64 + 合法 JSON，但缺少必要声明 → 内容被篡改
        String stripped = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"typ\":\"AT\"}".getBytes());
        String tampered = header + "." + stripped + "." + signature;
        assertError("载荷声明缺失", tampered, svc, TokenError.PAYLOAD_TAMPERED,
                "载荷可解析为 JSON 但缺少 sub/sid/jti/iat/exp 等必要声明");
    }

    @Test
    void badSignatureIsRejected() {
        TokenService svc = tokenServiceAt(1_000_000);
        String valid = svc.issueAccessToken("u-1", "s-1", "jti-1");
        String[] parts = valid.split("\\.");
        String forgedSignature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(new byte[32]);
        String tampered = parts[0] + "." + parts[1] + "." + forgedSignature;
        assertError("签名不匹配", tampered, svc, TokenError.SIGNATURE_INVALID,
                "结构与载荷均合法，但重算 HMAC 与随附签名不一致");
    }

    @Test
    void expiredTokenIsRejected() {
        TokenService issuer = tokenServiceAt(1_000_000);
        String access = issuer.issueAccessToken("u-1", "s-1", "jti-1");
        TokenService later = tokenServiceAt(1_000_000 + 301);
        assertError("访问令牌过期", access, later, TokenError.EXPIRED_TOKEN,
                "当前时间已超过载荷 exp 声明");
    }

    @Test
    void unsupportedTypeIsRejected() {
        TokenService svc = tokenServiceAt(1_000_000);
        // 用反射之外的方式：直接构造一个结构完整、签名正确但 typ 非法的令牌
        String weird = signRaw(svc, "{\"typ\":\"WEIRD\",\"sub\":\"u\",\"sid\":\"s\",\"jti\":\"j\","
                + "\"iat\":999999,\"exp\":9999999}");
        assertError("未知令牌类型", weird, svc, TokenError.UNSUPPORTED_TOKEN,
                "签名与有效期均通过，但 typ 既不是 AT 也不是 RT");
    }

    @Test
    void validTokenRoundTrips() {
        TokenService svc = tokenServiceAt(1_000_000);
        String token = svc.issueAccessToken("u-1", "s-1", "jti-1");
        TokenClaims claims = svc.verify(token);
        log.info("用例=合法令牌往返 输入={} 判定依据=结构/声明/HMAC/有效期全部通过 结果=sub={},sid={},typ={}",
                token, claims.subject(), claims.sessionId(), claims.type());
        assertEquals("u-1", claims.subject());
        assertEquals("s-1", claims.sessionId());
        assertEquals(TokenClaims.TYPE_ACCESS, claims.type());
    }

    /** 用 TokenService 自身的密钥对“自定义载荷”做正确签名，用于隔离类型判定。 */
    @SuppressWarnings("unchecked")
    private String signRaw(TokenService svc, String payloadJson) {
        try {
            Field keyField = TokenService.class.getDeclaredField("signingKey");
            keyField.setAccessible(true);
            javax.crypto.spec.SecretKeySpec key =
                    (javax.crypto.spec.SecretKeySpec) keyField.get(svc);
            String header = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\"}".getBytes());
            String payload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(payloadJson.getBytes());
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(key);
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal((header + "." + payload).getBytes()));
            return header + "." + payload + "." + sig;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
