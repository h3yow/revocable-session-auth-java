package com.github.h3yow.revocablesessionauthjava.security.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.time.Clock;

/**
 * 负责访问令牌 / 刷新令牌的签发与本地验签（HMAC-SHA256）。
 *
 * <p>线路格式（自定义结构，刻意保持依赖最小化）：
 * <pre>base64url(header).base64url(payload).base64url(hmacSha256(header.payload))</pre>
 *
 * <p>验签严格按下列顺序给出<b>可区分</b>的失败类别，且不向外泄露底层异常：
 * <ol>
 *   <li>缺失/空白 → MISSING_TOKEN</li>
 *   <li>不是三段式或 Base64/头部不可解码 → FORGED_TOKEN（伪造结构）</li>
 *   <li>载荷无法解析或声明缺失 → PAYLOAD_TAMPERED（内容被篡改）</li>
 *   <li>HMAC 不匹配 → SIGNATURE_INVALID（签名不匹配）</li>
 *   <li>类型不是 AT/RT → UNSUPPORTED_TOKEN</li>
 *   <li>已过期 → EXPIRED_TOKEN</li>
 * </ol>
 */
@Service
public class TokenService {

    private static final String HEADER = "{\"alg\":\"HS256\"}";

    private final Clock clock;
    private final SecretKeySpec signingKey;
    private final long accessTokenTtlSeconds;
    private final long refreshTokenTtlSeconds;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();
    private final Decoder urlDecoder = Base64.getUrlDecoder();

    public TokenService(Clock clock,
                        @Value("${app.security.token-secret:dev-secret-please-change-min-32-bytes}") String secret,
                        @Value("${app.security.access-token-ttl-seconds:300}") long accessTokenTtlSeconds,
                        @Value("${app.security.refresh-token-ttl-seconds:1209600}") long refreshTokenTtlSeconds) {
        this.clock = clock;
        this.signingKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public String issueAccessToken(String userId, String sessionId, String jti) {
        long now = clock.instant().getEpochSecond();
        return sign(new TokenClaims(TokenClaims.TYPE_ACCESS, userId, sessionId, jti,
                now, now + accessTokenTtlSeconds));
    }

    public String issueRefreshToken(String userId, String sessionId, String jti) {
        long now = clock.instant().getEpochSecond();
        return sign(new TokenClaims(TokenClaims.TYPE_REFRESH, userId, sessionId, jti,
                now, now + refreshTokenTtlSeconds));
    }

    /**
     * 验签并解析令牌。不校验类型语义（调用方按使用场景判断），但校验结构、声明、签名与有效期。
     */
    public TokenClaims verify(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException(TokenError.MISSING_TOKEN);
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            throw new AuthException(TokenError.FORGED_TOKEN);
        }
        byte[] headerBytes;
        byte[] payloadBytes;
        byte[] signatureBytes;
        try {
            headerBytes = urlDecoder.decode(parts[0]);
            payloadBytes = urlDecoder.decode(parts[1]);
            signatureBytes = urlDecoder.decode(parts[2]);
        } catch (IllegalArgumentException malformedBase64) {
            throw new AuthException(TokenError.FORGED_TOKEN);
        }

        JsonNode headerNode;
        try {
            headerNode = mapper.readTree(headerBytes);
        } catch (Exception notJson) {
            throw new AuthException(TokenError.FORGED_TOKEN);
        }
        if (headerNode == null || !"HS256".equals(headerNode.path("alg").asText(null))) {
            throw new AuthException(TokenError.FORGED_TOKEN);
        }

        JsonNode payloadNode;
        try {
            payloadNode = mapper.readTree(payloadBytes);
        } catch (Exception notJson) {
            throw new AuthException(TokenError.PAYLOAD_TAMPERED);
        }
        TokenClaims claims = readClaims(payloadNode);

        byte[] expected = hmac(parts[0] + "." + parts[1]);
        if (!constantTimeEquals(expected, signatureBytes)) {
            throw new AuthException(TokenError.SIGNATURE_INVALID);
        }

        if (!TokenClaims.TYPE_ACCESS.equals(claims.type()) && !TokenClaims.TYPE_REFRESH.equals(claims.type())) {
            throw new AuthException(TokenError.UNSUPPORTED_TOKEN);
        }
        if (claims.expiresAt() <= clock.instant().getEpochSecond()) {
            throw new AuthException(TokenError.EXPIRED_TOKEN);
        }
        return claims;
    }

    private TokenClaims readClaims(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new AuthException(TokenError.PAYLOAD_TAMPERED);
        }
        String type = node.path("typ").asText(null);
        String subject = node.path("sub").asText(null);
        String sessionId = node.path("sid").asText(null);
        String jti = node.path("jti").asText(null);
        JsonNode iat = node.get("iat");
        JsonNode exp = node.get("exp");
        if (type == null || subject == null || sessionId == null || jti == null
                || iat == null || exp == null || !iat.isNumber() || !exp.isNumber()) {
            throw new AuthException(TokenError.PAYLOAD_TAMPERED);
        }
        return new TokenClaims(type, subject, sessionId, jti, iat.asLong(), exp.asLong());
    }

    private String sign(TokenClaims claims) {
        try {
            String header = urlEncoder.encodeToString(HEADER.getBytes(StandardCharsets.UTF_8));
            byte[] payloadJson = mapper.createObjectNode()
                    .put("typ", claims.type())
                    .put("sub", claims.subject())
                    .put("sid", claims.sessionId())
                    .put("jti", claims.jti())
                    .put("iat", claims.issuedAt())
                    .put("exp", claims.expiresAt())
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);
            String payload = urlEncoder.encodeToString(payloadJson);
            String signingInput = header + "." + payload;
            String signature = urlEncoder.encodeToString(hmac(signingInput));
            return signingInput + "." + signature;
        } catch (Exception e) {
            // 签发失败属于服务端内部故障，绝不能把底层细节回传调用方
            throw new IllegalStateException("token issuance failed");
        }
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("signature computation failed");
        }
    }

    private boolean constantTimeEquals(byte[] expected, byte[] actual) {
        return MessageDigest.isEqual(expected, actual);
    }
}
