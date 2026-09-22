package com.github.h3yow.revocablesessionauthjava.security;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.AuthenticatedUser;
import com.github.h3yow.revocablesessionauthjava.domain.Role;
import com.github.h3yow.revocablesessionauthjava.domain.RotationOutcome;
import com.github.h3yow.revocablesessionauthjava.domain.Session;
import com.github.h3yow.revocablesessionauthjava.domain.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.domain.TokenPair;
import com.github.h3yow.revocablesessionauthjava.domain.User;
import com.github.h3yow.revocablesessionauthjava.security.session.SessionStore;
import com.github.h3yow.revocablesessionauthjava.security.token.TokenService;
import com.github.h3yow.revocablesessionauthjava.security.user.UserStore;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * 认证与授权应用服务。
 *
 * <p>关键一致性约定：
 * <ul>
 *   <li>刷新令牌一次性使用：轮换通过 {@link SessionStore#rotate} 的原子读改写完成，
 *       并发请求下恰好一个成功，其余得到 REUSE_DETECTED，且整个令牌族被撤销。</li>
 *   <li>访问令牌本身是短期不记名票据，不承载权限；每次请求都实时查询会话撤销位与
 *       用户最新角色，因此注销 / 权限变更无需等待令牌过期即生效。</li>
 *   <li>所有失败都归一为 {@link TokenError}，不向调用方透传底层异常。</li>
 * </ul>
 */
@Service
public class AuthService {

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserStore userStore;

    public AuthService(TokenService tokenService, SessionStore sessionStore, UserStore userStore) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userStore = userStore;
    }

    /** 用户名密码登录，建立会话并签发令牌对。 */
    public TokenPair login(String username, String password) {
        User user = userStore.findByUsername(username);
        if (user == null || !user.enabled() || !userStore.verifyPassword(user, password)) {
            // 不区分“用户不存在”与“密码错误”，避免账号枚举；对外统一为 BAD_CREDENTIALS
            throw new AuthException(TokenError.BAD_CREDENTIALS);
        }
        String sessionId = newId();
        String refreshJti = newId();
        String accessJti = newId();

        sessionStore.save(new Session(sessionId, user.id(), refreshJti, false, null));

        String accessToken = tokenService.issueAccessToken(user.id(), sessionId, accessJti);
        String refreshToken = tokenService.issueRefreshToken(user.id(), sessionId, refreshJti);
        return new TokenPair(accessToken, refreshToken, tokenService.accessTokenTtlSeconds());
    }

    /**
     * 使用刷新令牌换取新令牌对：旧刷新令牌立即失效，新旧令牌均不可再次使用。
     */
    public TokenPair refresh(String refreshToken) {
        TokenClaims claims = requireType(tokenService.verify(refreshToken), TokenClaims.TYPE_REFRESH);

        String nextRefreshJti = newId();
        String nextAccessJti = newId();
        RotationOutcome outcome = sessionStore.rotate(claims.sessionId(), claims.jti(), nextRefreshJti);

        switch (outcome.kind()) {
            case OK -> {
                Session session = outcome.session();
                User user = userStore.findById(session.userId());
                if (user == null || !user.enabled()) {
                    // 用户在会话存活期间被停用：不签发新票据
                    throw new AuthException(TokenError.USER_UNAVAILABLE);
                }
                String access = tokenService.issueAccessToken(user.id(), session.id(), nextAccessJti);
                String refresh = tokenService.issueRefreshToken(user.id(), session.id(), nextRefreshJti);
                return new TokenPair(access, refresh, tokenService.accessTokenTtlSeconds());
            }
            case UNKNOWN -> throw new AuthException(TokenError.UNKNOWN_SESSION);
            case REVOKED -> throw new AuthException(mapRevokeReason(outcome.session()));
            case REPLAYED -> throw new AuthException(TokenError.REUSE_DETECTED);
            default -> throw new AuthException(TokenError.UNKNOWN_SESSION);
        }
    }

    /** 注销：撤销会话，使此前签发的访问令牌立即失效。 */
    public void logout(String refreshToken) {
        TokenClaims claims = requireType(tokenService.verify(refreshToken), TokenClaims.TYPE_REFRESH);
        sessionStore.revoke(claims.sessionId());
    }

    /** 管理操作：直接撤销指定会话。 */
    public void revokeSession(String sessionId) {
        sessionStore.revoke(sessionId);
    }

    /**
     * 变更用户角色：整体原子替换。变更后，该用户此前签发的访问令牌在下次请求时
     * 会按新角色实时聚合权限（无需等待令牌过期，也不经过缓存）。
     */
    public User changeRoles(String userId, java.util.List<String> roleNames) {
        java.util.EnumSet<Role> newRoles = java.util.EnumSet.noneOf(Role.class);
        for (String name : roleNames) {
            try {
                newRoles.add(Role.valueOf(name));
            } catch (IllegalArgumentException unknownRole) {
                // 不把入参细节/枚举值直接暴露为底层异常，统一归为格式问题
                throw new IllegalArgumentException("unknown role");
            }
        }
        User updated = userStore.replaceRoles(userId, newRoles);
        if (updated == null) {
            throw new AuthException(TokenError.USER_UNAVAILABLE);
        }
        return updated;
    }

    /**
     * 校验访问令牌并返回认证主体。
     * 依次区分：缺失 / 伪造 / 篡改 / 签名 / 类型 / 过期 / 会话撤销 / 用户停用。
     * 权限不在此处判定，也不信任令牌中的任何角色快照。
     */
    public AuthenticatedUser authenticateAccessToken(String rawToken) {
        TokenClaims claims = requireType(tokenService.verify(rawToken), TokenClaims.TYPE_ACCESS);

        Session session = sessionStore.findById(claims.sessionId());
        if (session == null) {
            throw new AuthException(TokenError.UNKNOWN_SESSION);
        }
        if (session.revoked()) {
            throw new AuthException(mapRevokeReason(session));
        }
        User user = userStore.findById(claims.subject());
        if (user == null || !user.enabled()) {
            throw new AuthException(TokenError.USER_UNAVAILABLE);
        }
        if (!user.id().equals(session.userId())) {
            // 令牌主体与会话归属不一致，按伪造处理，不暴露具体差异
            throw new AuthException(TokenError.SIGNATURE_INVALID);
        }
        return new AuthenticatedUser(user.id(), user.username(), session.id());
    }

    /**
     * 实时权限判定：每次都重新读取用户当前角色集合并聚合权限，
     * 因此角色变更对已签发的访问令牌立即生效，不存在缓存放行窗口。
     */
    public void authorize(AuthenticatedUser principal, String permission) {
        User user = userStore.findById(principal.userId());
        if (user == null || !user.enabled()) {
            throw new AuthException(TokenError.USER_UNAVAILABLE);
        }
        for (Role role : user.roles()) {
            if (role.permissions().contains(permission)) {
                return;
            }
        }
        throw new AuthException(TokenError.ACCESS_DENIED);
    }

    private TokenClaims requireType(TokenClaims claims, String expectedType) {
        if (!expectedType.equals(claims.type())) {
            throw new AuthException(TokenError.UNSUPPORTED_TOKEN);
        }
        return claims;
    }

    private TokenError mapRevokeReason(Session session) {
        if (session != null && session.revokeReason() == TokenError.REUSE_DETECTED) {
            return TokenError.REUSE_DETECTED;
        }
        return TokenError.REVOKED_SESSION;
    }

    private String newId() {
        return UUID.randomUUID().toString();
    }
}
