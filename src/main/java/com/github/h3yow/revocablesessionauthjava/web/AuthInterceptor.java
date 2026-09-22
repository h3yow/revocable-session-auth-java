package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import com.github.h3yow.revocablesessionauthjava.auth.Authentication;
import com.github.h3yow.revocablesessionauthjava.auth.AuthService;
import com.github.h3yow.revocablesessionauthjava.auth.Permissions;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 鉴权拦截器，未认证与越权给出不同结论：
 * <ol>
 *   <li>Authorization 头缺失 -> MISSING_TOKEN；存在但非 Bearer/为空 -> MALFORMED_TOKEN；</li>
 *   <li>令牌校验由 AuthService 完成，过期/撤销/篡改等分类透传；</li>
 *   <li>@RequirePermission 不满足 -> ACCESS_DENIED（区别于未认证类失败）。</li>
 * </ol>
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String AUTHENTICATION_ATTRIBUTE =
            "com.github.h3yow.revocablesessionauthjava.authentication";
    private static final String BEARER_PREFIX = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);

    private final AuthService authService;

    public AuthInterceptor(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        log.debug("拦截判定 path={} method={}", request.getRequestURI(), request.getMethod());

        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            throw new AuthException(AuthFailureReason.MISSING_TOKEN,
                    "Authorization header absent for " + request.getRequestURI());
        }
        if (!header.startsWith(BEARER_PREFIX)) {
            throw new AuthException(AuthFailureReason.MALFORMED_TOKEN,
                    "Authorization scheme must be Bearer");
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            throw new AuthException(AuthFailureReason.MISSING_TOKEN, "Bearer token is empty");
        }

        Authentication authentication = authService.authenticateAccessToken(token);
        request.setAttribute(AUTHENTICATION_ATTRIBUTE, authentication);

        RequirePermission required = resolveAnnotation(handlerMethod);
        if (required != null && !Permissions.satisfies(authentication.permissions(), required.value())) {
            log.info("拦截判定结果 reason=ACCESS_DENIED basis=权限不足 path={} username={} required={} granted={}",
                    request.getRequestURI(), authentication.username(),
                    java.util.Arrays.toString(required.value()), authentication.permissions());
            throw new AuthException(AuthFailureReason.ACCESS_DENIED,
                    "requires one of " + java.util.Arrays.toString(required.value()));
        }
        return true;
    }

    private RequirePermission resolveAnnotation(HandlerMethod handlerMethod) {
        RequirePermission onMethod = handlerMethod.getMethodAnnotation(RequirePermission.class);
        if (onMethod != null) {
            return onMethod;
        }
        return handlerMethod.getBeanType().getAnnotation(RequirePermission.class);
    }

    /** 供控制器读取当前请求的认证主体。 */
    public static Authentication currentAuthentication(HttpServletRequest request) {
        Object value = request.getAttribute(AUTHENTICATION_ATTRIBUTE);
        return value instanceof Authentication auth ? auth : null;
    }
}
