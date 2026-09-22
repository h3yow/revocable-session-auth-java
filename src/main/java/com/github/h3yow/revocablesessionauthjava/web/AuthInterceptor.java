package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.AuthenticatedUser;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.security.AuthService;
import com.github.h3yow.revocablesessionauthjava.security.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 认证 + 授权拦截器。
 *
 * <p>判定顺序（每一步失败都给出独立可区分类别）：
 * 提取 Bearer → 缺失拒绝 → 实时校验访问令牌（含会话撤销位）→ 按 @RequirePermission 鉴权。
 * ThreadLocal 仅保存最终通过认证的主体，并在 afterCompletion 中无条件清理。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService authService;

    public AuthInterceptor(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequirePermission required = handlerMethod.getMethodAnnotation(RequirePermission.class);
        if (required == null) {
            return true;
        }

        String header = request.getHeader("Authorization");
        String rawToken = extractBearer(header);
        if (rawToken == null) {
            log.info("访问被拒 path={} 依据=Authorization头缺失或非Bearer方案 结果={}",
                    request.getRequestURI(), TokenError.MISSING_TOKEN.name());
            throw new AuthException(TokenError.MISSING_TOKEN);
        }

        AuthenticatedUser principal = authService.authenticateAccessToken(rawToken);
        SecurityContext.set(principal);
        log.info("认证通过 path={} user={} session={} 依据=访问令牌验签通过且会话未撤销",
                request.getRequestURI(), principal.userId(), principal.sessionId());

        authService.authorize(principal, required.value());
        log.info("授权通过 path={} user={} 依据=实时聚合当前角色包含权限[{}]",
                request.getRequestURI(), principal.userId(), required.value());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        SecurityContext.clear();
    }

    /**
     * 仅接受 "Bearer &lt;token&gt;" 形式；空头、空白票据、其它方案一律视为凭证缺失。
     */
    private String extractBearer(String header) {
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
