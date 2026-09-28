package com.github.h3yow.revocablesessionauthjava.auth;

import com.github.h3yow.revocablesessionauthjava.token.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.token.TokenService;
import java.time.Clock;
import java.util.List;
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
 *   <li><b>强制下线与刷新不抢时序</b>：刷新的“查撤销位 + 签发新令牌对”临界区与
 *       强制下线的“置撤销位”在同一把 {@link Session#lock()} 上串行，
 *       撤销要么在刷新之前（刷新被 SESSION_REVOKED 拒绝，不会救活会话），
 *       要么在刷新之后（新令牌引用已撤销会话，下一次请求立即被拒）。</li>
 *   <li><b>权限变更</b>：角色变更提升会话 version，旧访问令牌因版本不符得到
 *       {@link AuthFailureReason#SESSION_STATE_CHANGED}；刷新/重新登录后按新角色判定。</li>
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

        // 阶段2：服务端登记查询：jti 无登记 -> UNKNOWN_TOKEN
        RefreshTokenRecord record = sessionStore.findRefreshToken(claims.tokenId())
                .orElseThrow(() -> {
                    log.info("刷新结果 reason=UNKNOWN_TOKEN basis=服务端无此刷新令牌登记 jti={}", claims.tokenId());
                    return new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                            "refresh token not registered, jti=" + claims.tokenId());
                });

        // 阶段3：CAS 抢占 —— 并发下只有一个线程能把 false 翻成 true
        if (!record.used().compareAndSet(false, true)) {
            log.info("刷新结果 reason=REFRESH_TOKEN_REUSED basis=刷新令牌 used=true jti={} sessionId={}",
                    record.jti(), record.sessionId());
            throw new AuthException(AuthFailureReason.REFRESH_TOKEN_REUSED,
                    "refresh token already used, jti=" + record.jti());
        }

        // 阶段4：回查登记指向的会话：不存在 -> SESSION_NOT_FOUND
        Session session = sessionStore.findSession(record.sessionId())
                .orElseThrow(() -> {
                    log.info("刷新结果 reason=SESSION_NOT_FOUND basis=会话不存在 jti={} sessionId={}",
                            record.jti(), record.sessionId());
                    return new AuthException(AuthFailureReason.SESSION_NOT_FOUND,
                            "session missing, id=" + record.sessionId());
                });
        // 会话真实存在但与令牌声称的会话/主体不一致 -> TOKEN_SESSION_MISMATCH（拿了别的会话的令牌）
        if (!record.sessionId().equals(claims.sessionId())
                || !session.username().equals(claims.username())) {
            log.info("刷新结果 reason=TOKEN_SESSION_MISMATCH basis=令牌 claims(sessionId={},username={}) 与登记/会话(sessionId={},username={}) 不一致",
                    claims.sessionId(), claims.username(), record.sessionId(), session.username());
            throw new AuthException(AuthFailureReason.TOKEN_SESSION_MISMATCH,
                    "token does not match its registered session");
        }

        // 阶段5：会话级临界区 —— 与强制下线/注销的撤销动作互斥，杜绝“撤销后被刷新救活”
        synchronized (session.lock()) {
            if (session.revoked()) {
                log.info("刷新结果 reason=SESSION_REVOKED basis=会话 revoked=true jti={} sessionId={}",
                        record.jti(), session.id());
                throw new AuthException(AuthFailureReason.SESSION_REVOKED,
                        "session revoked, id=" + session.id());
            }
            session.touch(clock.millis());
            TokenPair pair = issuePair(session);
            log.info("刷新结果 SUCCESS basis=令牌有效且 CAS 抢占成功（会话锁内复核未撤销）jti={} sessionId={} -> 旧刷新令牌立即失效",
                    record.jti(), session.id());
            return pair;
        }
    }

    @Override
    public void logout(String rawRefreshToken) {
        log.info("注销判定 input.refreshToken={}", abbreviate(rawRefreshToken));
        TokenClaims claims = tokenService.parseAndVerify(rawRefreshToken, TokenType.REFRESH);
        RefreshTokenRecord record = sessionStore.findRefreshToken(claims.tokenId())
                .orElseThrow(() -> new AuthException(AuthFailureReason.UNKNOWN_TOKEN,
                        "refresh token not registered, jti=" + claims.tokenId()));
        // 撤销走会话锁；会话若已不存在视为已注销，结论保持 200（与历史行为一致、可重复）
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
                    log.info("访问判定结果 reason=SESSION_NOT_FOUND basis=服务端无此会话 jti={} sessionId={}",
                            claims.tokenId(), claims.sessionId());
                    return new AuthException(AuthFailureReason.SESSION_NOT_FOUND,
                            "session missing, id=" + claims.sessionId());
                });
        if (session.revoked()) {
            log.info("访问判定结果 reason=SESSION_REVOKED basis=会话 revoked=true jti={} sessionId={}",
                    claims.tokenId(), session.id());
            throw new AuthException(AuthFailureReason.SESSION_REVOKED, "session revoked, id=" + session.id());
        }
        if (!session.username().equals(claims.username())) {
            log.info("访问判定结果 reason=TOKEN_SESSION_MISMATCH basis=令牌 username={} 与会话 username={} 不一致",
                    claims.username(), session.username());
            throw new AuthException(AuthFailureReason.TOKEN_SESSION_MISMATCH,
                    "token subject does not match session");
        }
        if (claims.version() != session.version()) {
            log.info("访问判定结果 reason=SESSION_STATE_CHANGED basis=令牌版本{} != 会话版本{} jti={} sessionId={}",
                    claims.version(), session.version(), claims.tokenId(), session.id());
            throw new AuthException(AuthFailureReason.SESSION_STATE_CHANGED,
                    "tokenVersion=" + claims.version() + ", sessionVersion=" + session.version());
        }

        // 角色/权限实时取自会话，绝不信任令牌自携带内容
        Authentication auth = new Authentication(
                session.username(), session.id(), claims.tokenId(),
                Set.copyOf(session.roles()), Set.copyOf(session.permissions()));
        log.info("访问判定结果 SUCCESS basis=签名有效+会话未撤销+归属一致+版本一致 jti={} sessionId={} permissions={}",
                claims.tokenId(), session.id(), auth.permissions());
        return auth;
    }

    @Override
    public int changeRoles(String username, Set<String> newRoles) {
        log.info("权限变更判定 input.username={} newRoles={}", username, newRoles);
        requireExistingUser(username);
        Set<String> safeRoles = newRoles == null ? Set.of() : Set.copyOf(newRoles);
        Set<String> permissions = Permissions.forRoles(safeRoles);
        // 角色落盘：后续重新登录即按新角色签发
        userDirectory.updateRoles(username, safeRoles);
        int affected = 0;
        for (Session session : sessionStore.findSessionsByUsername(username)) {
            synchronized (session.lock()) {
                session.updateRoles(safeRoles, permissions);
            }
            affected++;
        }
        log.info("权限变更结果 SUCCESS basis=目录已更新、{} 个会话提升版本 -> 旧访问令牌将以 SESSION_STATE_CHANGED 拒绝",
                affected);
        return affected;
    }

    @Override
    public SessionOverviewResponse listActiveSessions(String username) {
        log.info("管理员会话概览判定 input.username={}", username);
        requireExistingUser(username);
        List<Session> active = sessionStore.findActiveSessionsByUsername(username);
        List<SessionOverview> overviews = active.stream().map(SessionOverview::from).toList();
        log.info("管理员会话概览结果 SUCCESS username={} activeSessions={}", username, overviews.size());
        return new SessionOverviewResponse(username, overviews.size(), overviews);
    }

    @Override
    public SessionRevocationResult revokeSession(String sessionId) {
        log.info("管理员强制下线判定 input.sessionId={}", sessionId);
        Session session = sessionStore.findSession(sessionId).orElse(null);
        if (session == null) {
            // 不存在：稳定可重复，不冒底层错误
            log.info("管理员强制下线结果 reason=NOT_FOUND basis=服务端无此会话 sessionId={}", sessionId);
            return new SessionRevocationResult(sessionId, false, false, false);
        }
        boolean alreadyRevoked;
        synchronized (session.lock()) {
            alreadyRevoked = session.revoked();
            session.revoke();
        }
        log.info("管理员强制下线结果 SUCCESS sessionId={} alreadyRevoked={} -> 已签发令牌下一次请求立即失效",
                sessionId, alreadyRevoked);
        return new SessionRevocationResult(sessionId, true, true, alreadyRevoked);
    }

    @Override
    public UserRevocationResult revokeUserSessions(String username) {
        log.info("管理员批量强制下线判定 input.username={}", username);
        requireExistingUser(username);
        List<Session> active = sessionStore.findActiveSessionsByUsername(username);
        List<String> revokedIds;
        // 逐条在各自会话锁内撤销；其他用户的会话完全不触碰
        revokedIds = active.stream()
                .filter(s -> {
                    synchronized (s.lock()) {
                        if (s.revoked()) {
                            return false;
                        }
                        s.revoke();
                        return true;
                    }
                })
                .map(Session::id)
                .toList();
        log.info("管理员批量强制下线结果 SUCCESS username={} revokedSessions={}", username, revokedIds.size());
        return new UserRevocationResult(username, revokedIds.size(), revokedIds);
    }

    private void requireExistingUser(String username) {
        if (userDirectory.findByUsername(username == null ? "" : username).isEmpty()) {
            log.info("管理员操作结果 reason=USER_NOT_FOUND basis=用户目录无此用户 username={}", username);
            throw new AuthException(AuthFailureReason.USER_NOT_FOUND, "user not found: " + username);
        }
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
