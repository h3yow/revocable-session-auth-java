package com.github.h3yow.revocablesessionauthjava.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import org.slf4j.Logger;

/** 断言抛出的失败原因与预期分类一一对应，并打印结果日志。 */
public final class AuthAssertions {

    private AuthAssertions() {
    }

    public static AuthException assertFailure(Logger log, AuthFailureReason expected, Runnable action) {
        AuthException ex = assertThrows(AuthException.class, action::run);
        assertEquals(expected, ex.reason(),
                "期望失败分类 " + expected + "，实际 " + ex.reason());
        AuthTestLogger.result(log, "按预期被拒绝 reason={} description={}",
                ex.reason().code(), ex.reason().description());
        return ex;
    }
}
