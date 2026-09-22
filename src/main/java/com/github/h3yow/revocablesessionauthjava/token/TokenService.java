package com.github.h3yow.revocablesessionauthjava.token;

import com.github.h3yow.revocablesessionauthjava.auth.TokenType;

/**
 * 令牌签发与校验。令牌格式：base64url(claims JSON).base64url(HMAC-SHA256 签名)。
 * 校验时区分：格式错误、签名不匹配/篡改、过期等失败类别。
 */
public interface TokenService {

    TokenClaims issue(String sessionId, String username, long sessionVersion, TokenType type);

    String sign(TokenClaims claims);

    TokenClaims parseAndVerify(String compactToken, TokenType expectedType);
}
