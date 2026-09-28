package com.github.h3yow.revocablesessionauthjava.auth;

import com.github.h3yow.revocablesessionauthjava.token.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.token.TokenService;
import java.time.Clock;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 默认认证服务。关键一致性设计：
 * <ul>
 *   <li><b>刷新轮换</b>：每次刷新签发全新 jti 的访问+刷新令牌；旧刷新令牌通过
 *       {@link RefreshTokenRecord#used()} 的 CAS 抢占立即失效，并发请求仅一个成功，
 *       其余得到 {@link AuthFailureReason#REFRESH_TOKEN_REUSED}。</li>
 *   <li><b>撤销即时生效</b>：访问令牌本身不含权限结论，每次请求都实时回查
 *       {@link SessionStore}，revoked=true 立即拒绝，不存在缓存/时序放行窗口。</li>
 *   <li><b>权限变更</b>：角色变更提升会话 version，旧访问令牌因版本不符得到
 *       {@link AuthFailureReason#SESSION_STATE_CHANGED}；刷新后签发的新令牌携带新角色。</li>
 * </ul>
 */
@Service
public class DefaultAuthService implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthService.class);

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserDirectory userDirectory;
    private final Clock clock;
    private final long accessTtlSeconds;

    public DefaultAuthService(
            TokenService tokenService,
            SessionStore sessionStore,
            UserDirectory userDirectory,
            Clock clock,
            @Value("${app.auth.access-token-ttl-seconds}") long accessTtlSeconds) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.accessTtlSeconds = accessTtlSeconds;
    }

    @Override
    public TokenPair login(String username, String password) {
        log.info("登录判定 input.username={}", username);
        UserAccount account = userDirectory.findByUsername(username == null ? "" : username)
                .orElseThrow(() -> {
                    log.info("登录结果 reason=BAD_CREDENTIALS basis=用户不存在 username={}", username);
                    return new AuthException(AuthFailureReason.BAD_CREDENTIALS, "user not found");
                });
        if (password == null || !account.password().equals(password)) {
            log.info("登录结果 reason=BAD_CREDENTIALS basis=密码不匹配 username={}", username);
            throw new AuthException(AuthFailureReason.BAD_CREDENTIALS, "password mismatch");
        }

        Set<String> permissions = Permissions.forRoles(account.roles());
        Session session = new Session(
                "sess-" + UUID.randomUUID(), account.username(), account.roles(), permissions,
                clock.millis());
        sessionStore.saveSession(session);
        TokenPair pair = issuePair(session);
        log.info("登录结果 SUCCESS basis=凭据匹配 username={} sessionId={} refreshJti 已登记",
                username, session.id());
        return pair;
    }

    @Override
    public TokenPair refresh(String rawRefreshToken) {
        String tokenRef = abbreviate(rawRefreshToken);
        log.info("刷新判定 input.refreshToken={}", tokenRef);

        // 阶段1：无状态校验（签名/过期/类型），失败分类由 TokenService 给出
        TokenClaims claims = tokenService.parseAndVerify(rawRefreshToken, TokenType.REFRESH);

        // 阶段2：服务端登记查询
        RefreshTokenRecord record = sessionStore.findRefreshToken(claims.tokenId())
                .orElseThrow(() -> {
                    log.info("刷新结果 reason=UNKNOWN_TOKEN basis=服务端无此刷新令牌登记 jti={}", claims.tokenId());
                    return new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                            "refresh token not registered, jti=" + claims.tokenId());
                });

        // 阶段2.5：令牌声明与服务端登记必须一致（防止拼接/挪用其他会话的令牌）
        if (!record.sessionId().equals(claims.sessionId())) {
            log.info("刷新结果 reason=SESSION_TOKEN_MISMATCH basis=登记会话{} != 声明会话{} jti={}",
                    record.sessionId(), claims.sessionId(), claims.tokenId());
            throw new AuthException(AuthFailureReason.SESSION_TOKEN_MISMATCH,
                    "refresh token registered to different session, jti=" + claims.tokenId());
        }

        // 阶段3：CAS 抢占 —— 并发下只有一个线程能把 false 翻成 true
        if (!record.used().compareAndSet(false, true)) {
            log.info("刷新结果 reason=REFRESH_TOKEN_REUSED basis=刷新令牌 used=true jti={} sessionId={}",
                    record.jti(), record.sessionId());
            throw new AuthException(AuthFailureReason.REFRESH_TOKEN_REUSED,
                    "refresh token already used, jti=" + record.jti());
        }

        // 阶段4：回查会话（撤销在抢占之后判定：被撤销会话的令牌只能消费一次）
        Session session = sessionStore.findSession(record.sessionId())
                .orElseThrow(() -> {
                    log.info("刷新结果 reason=UNKNOWN_TOKEN basis=会话不存在 jti={} sessionId={}",
                            record.jti(), record.sessionId());
                    return new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                            "session missing, id=" + record.sessionId());
                });
        if (!session.username().equals(claims.username())) {
            log.info("刷新结果 reason=SESSION_TOKEN_MISMATCH basis=会话主体{} != 声明主体{} jti={}",
                    session.username(), claims.username(), claims.tokenId());
            throw new AuthException(AuthFailureReason.SESSION_TOKEN_MISMATCH,
                    "token subject differs from session owner, jti=" + claims.tokenId());
        }

        // 阶段5：与 revoke() 互斥的临界区 —— 撤销与"判定未撤销+签发"不会交错，
        // 强制下线要么先于刷新生效（本次刷新得到 SESSION_REVOKED），
        // 要么晚于签发（新令牌随会话撤销立即失效），不存在撤销后被刷新"救活"的窗口。
        TokenPair pair;
        synchronized (session) {
            if (session.revoked()) {
                log.info("刷新结果 reason=SESSION_REVOKED basis=会话 revoked=true jti={} sessionId={}",
                        record.jti(), session.id());
                throw new AuthException(AuthFailureReason.SESSION_REVOKED,
                        "session revoked, id=" + session.id());
            }
            pair = issuePair(session);
            session.touch(clock.millis());
        }
        log.info("刷新结果 SUCCESS basis=令牌有效且 CAS 抢占成功 jti={} sessionId={} -> 旧刷新令牌立即失效",
                record.jti(), session.id());
        return pair;
    }

    @Override
    public void logout(String rawRefreshToken) {
        log.info("注销判定 input.refreshToken={}", abbreviate(rawRefreshToken));
        TokenClaims claims = tokenService.parseAndVerify(rawRefreshToken, TokenType.REFRESH);
        RefreshTokenRecord record = sessionStore.findRefreshToken(claims.tokenId())
                .orElseThrow(() -> new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                        "refresh token not registered, jti=" + claims.tokenId()));
        sessionStore.revokeSession(record.sessionId());
        log.info("注销结果 SUCCESS basis=会话已撤销 sessionId={} -> 该会话已签发访问令牌将立即被拒绝",
                record.sessionId());
    }

    @Override
    public Authentication authenticateAccessToken(String rawAccessToken) {
        String tokenRef = abbreviate(rawAccessToken);
        log.info("访问令牌判定 input.accessToken={}", tokenRef);

        // 无状态校验：缺失/格式/签名篡改/过期/类型错误在此分类
        TokenClaims claims = tokenService.parseAndVerify(rawAccessToken, TokenType.ACCESS);

        Session session = sessionStore.findSession(claims.sessionId())
                .orElseThrow(() -> {
                    log.info("访问判定结果 reason=UNKNOWN_TOKEN basis=服务端无此会话 jti={} sessionId={}",
                            claims.tokenId(), claims.sessionId());
                    return new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                            "session missing, id=" + claims.sessionId());
                });
        if (!session.username().equals(claims.username())) {
            log.info("访问判定结果 reason=SESSION_TOKEN_MISMATCH basis=会话主体{} != 声明主体{} jti={} sessionId={}",
                    session.username(), claims.username(), claims.tokenId(), session.id());
            throw new AuthException(AuthFailureReason.SESSION_TOKEN_MISMATCH,
                    "token subject differs from session owner, jti=" + claims.tokenId());
        }
        if (session.revoked()) {
            log.info("访问判定结果 reason=SESSION_REVOKED basis=会话 revoked=true jti={} sessionId={}",
                    claims.tokenId(), session.id());
            throw new AuthException(AuthFailureReason.SESSION_REVOKED, "session revoked, id=" + session.id());
        }
        if (claims.version() != session.version()) {
            log.info("访问判定结果 reason=SESSION_STATE_CHANGED basis=令牌版本{} != 会话版本{} jti={} sessionId={}",
                    claims.version(), session.version(), claims.tokenId(), session.id());
            throw new AuthException(AuthFailureReason.SESSION_STATE_CHANGED,
                    "tokenVersion=" + claims.version() + ", sessionVersion=" + session.version());
        }

        // 角色/权限实时取自会话，绝不信任令牌自携带内容
        session.touch(clock.millis());
        Authentication auth = new Authentication(
                session.username(), session.id(), claims.tokenId(),
                Set.copyOf(session.roles()), Set.copyOf(session.permissions()));
        log.info("访问判定结果 SUCCESS basis=签名有效+会话未撤销+版本一致 jti={} sessionId={} permissions={}",
                claims.tokenId(), session.id(), auth.permissions());
        return auth;
    }

    @Override
    public void changeRoles(String username, Set<String> newRoles) {
        log.info("权限变更判定 input.username={} newRoles={}", username, newRoles);
        Set<String> safeRoles = newRoles == null ? Set.of() : Set.copyOf(newRoles);
        Set<String> permissions = Permissions.forRoles(safeRoles);
        boolean accountUpdated = userDirectory.updateRoles(username, safeRoles);
        int affected = 0;
        for (Session session : sessionStore.findSessionsByUsername(username)) {
            session.updateRoles(safeRoles, permissions);
            affected++;
        }
        log.info("权限变更结果 SUCCESS basis=账户目录更新={} 更新 {} 个会话并提升版本 -> 旧访问令牌将以 SESSION_STATE_CHANGED 拒绝",
                accountUpdated, affected);
    }

    private TokenPair issuePair(Session session) {
        TokenClaims access = tokenService.issue(session.id(), session.username(), session.version(), TokenType.ACCESS);
        TokenClaims refresh = tokenService.issue(session.id(), session.username(), session.version(), TokenType.REFRESH);
        sessionStore.saveRefreshToken(
                new RefreshTokenRecord(refresh.tokenId(), session.id(), refresh.expiresAt()));
        return new TokenPair(tokenService.sign(access), tokenService.sign(refresh),
                "Bearer", accessTtlSeconds);
    }

    private static String abbreviate(String token) {
        if (token == null) {
            return "<null>";
        }
        return token.length() <= 24 ? token : token.substring(0, 16) + "...(len=" + token.length() + ")";
    }
}
