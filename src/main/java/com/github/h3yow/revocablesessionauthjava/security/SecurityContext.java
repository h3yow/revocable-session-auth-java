package com.github.h3yow.revocablesessionauthjava.security;

import com.github.h3yow.revocablesessionauthjava.domain.AuthenticatedUser;

/**
 * 基于 ThreadLocal 的请求级安全上下文。拦截器在请求结束时必须清理。
 */
public final class SecurityContext {

    private static final ThreadLocal<AuthenticatedUser> CURRENT = new ThreadLocal<>();

    private SecurityContext() {
    }

    public static void set(AuthenticatedUser user) {
        CURRENT.set(user);
    }

    public static AuthenticatedUser get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
