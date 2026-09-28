package com.github.h3yow.revocablesessionauthjava.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import com.github.h3yow.revocablesessionauthjava.auth.TokenType;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * HMAC-SHA256 紧凑令牌：base64url(claims JSON) + "." + base64url(HMAC-SHA256(claims, secret))。
 * <p>
 * 校验顺序与失败分类（对外仅给分类，底层异常只记日志）：
 * <ol>
 *   <li>结构/编码无法解析 -> MALFORMED_TOKEN</li>
 *   <li>签名段根本不具备 HMAC-SHA256 输出形态（长度不符、明显伪造）-> INVALID_SIGNATURE</li>
 *   <li>签名形态合法但与重算值不一致：payload 被篡改，或由别的密钥签发 -> TAMPERED_TOKEN</li>
 *   <li>签名通过但 claims JSON/必填字段非法 -> MALFORMED_TOKEN</li>
 *   <li>expiresAt &lt;= now -> EXPIRED</li>
 *   <li>令牌类型与使用场景不符 -> WRONG_TOKEN_TYPE</li>
 * </ol>
 */
@Component
public class HmacTokenService implements TokenService {

    private static final Logger log = LoggerFactory.getLogger(HmacTokenService.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final Clock clock;
    private final byte[] secret;
    private final long accessTtlMillis;
    private final long refreshTtlMillis;

    public HmacTokenService(
            Clock clock,
            @Value("${app.auth.hmac-secret}") String secret,
            @Value("${app.auth.access-token-ttl-seconds}") long accessTtlSeconds,
            @Value("${app.auth.refresh-token-ttl-seconds}") long refreshTtlSeconds) {
        this.clock = clock;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTtlMillis = accessTtlSeconds * 1000L;
        this.refreshTtlMillis = refreshTtlSeconds * 1000L;
    }

    @Override
    public TokenClaims issue(String sessionId, String username, long sessionVersion, TokenType type) {
        long now = clock.millis();
        long ttl = type == TokenType.REFRESH ? refreshTtlMillis : accessTtlMillis;
        return new TokenClaims(
                UUID.randomUUID().toString(),
                sessionId,
                username,
                type,
                sessionVersion,
                now,
                now + ttl);
    }

    @Override
    public String sign(TokenClaims claims) {
        try {
            byte[] claimsBytes = objectMapper.writeValueAsBytes(claims);
            String payload = encoder.encodeToString(claimsBytes);
            String signature = encoder.encodeToString(hmac(payload));
            return payload + "." + signature;
        } catch (Exception e) {
            // 签发是本地可控操作，失败属于服务端内部错误，不向调用方透传
            log.error("签发令牌失败 sessionId={} type={}", claims.sessionId(), claims.type(), e);
            throw new AuthException(AuthFailureReason.MALFORMED_TOKEN, "token signing failed: " + e.getClass().getSimpleName());
        }
    }

    @Override
    public TokenClaims parseAndVerify(String compactToken, TokenType expectedType) {
        if (compactToken == null || compactToken.isBlank()) {
            throw new AuthException(AuthFailureReason.MISSING_TOKEN, "token is null or blank");
        }
        int dot = compactToken.lastIndexOf('.');
        if (dot <= 0 || dot == compactToken.length() - 1
                || compactToken.indexOf('.', dot + 1) >= 0) {
            throw malformed(compactToken, "结构必须为 payload.signature 两段");
        }
        String payload = compactToken.substring(0, dot);
        String signaturePart = compactToken.substring(dot + 1);

        byte[] signature;
        byte[] claimsBytes;
        try {
            signature = decoder.decode(signaturePart);
            claimsBytes = decoder.decode(payload);
        } catch (IllegalArgumentException e) {
            throw malformed(compactToken, "base64url 解码失败: " + e.getClass().getSimpleName());
        }

        // 签名段连 HMAC-SHA256 的输出形态都不具备：属于伪造/拼接的签名，而非"内容被改动"
        if (signature.length != 32) {
            log.warn("签名长度不符合 HmacSHA256 输出 expectedType={} actualLen={}",
                    expectedType, signature.length);
            throw new AuthException(AuthFailureReason.INVALID_SIGNATURE,
                    "signature length is " + signature.length);
        }

        byte[] expected = hmac(payload);
        if (!constantTimeEquals(expected, signature)) {
            // 签名形态合法但与重算值不一致：payload 在传输中被改动，或令牌由别的密钥签发。
            // 两种情形对校验端的可观测结论一致——随附签名不能证明当前内容，归为内容篡改。
            log.warn("令牌内容与签名不一致（payload 被篡改或跨密钥签发） expectedType={}", expectedType);
            throw new AuthException(AuthFailureReason.TAMPERED_TOKEN, "signature does not match payload");
        }

        TokenClaims claims;
        try {
            claims = objectMapper.readValue(claimsBytes, TokenClaims.class);
        } catch (Exception e) {
            throw malformed(compactToken, "claims JSON 解析失败: " + e.getClass().getSimpleName());
        }
        if (claims.tokenId() == null || claims.sessionId() == null || claims.type() == null) {
            throw malformed(compactToken, "claims 缺少必填字段");
        }

        if (claims.expiresAt() <= clock.millis()) {
            log.debug("令牌已过期 jti={} type={} expiresAt={}", claims.tokenId(), claims.type(), claims.expiresAt());
            throw new AuthException(AuthFailureReason.EXPIRED,
                    "token expired at " + claims.expiresAt());
        }
        if (claims.type() != expectedType) {
            log.debug("令牌类型不匹配 jti={} actual={} expected={}", claims.tokenId(), claims.type(), expectedType);
            throw new AuthException(AuthFailureReason.WRONG_TOKEN_TYPE,
                    "actual=" + claims.type() + ", expected=" + expectedType);
        }
        return claims;
    }

    private AuthException malformed(String compactToken, String detail) {
        log.warn("令牌格式不合法 len={} detail={}", compactToken == null ? 0 : compactToken.length(), detail);
        return new AuthException(AuthFailureReason.MALFORMED_TOKEN, detail);
    }

    private byte[] hmac(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 初始化失败", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
