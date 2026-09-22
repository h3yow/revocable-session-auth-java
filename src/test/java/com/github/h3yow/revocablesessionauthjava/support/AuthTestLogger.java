package com.github.h3yow.revocablesessionauthjava.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 统一的单测日志助手：每个判定都打印【输入】【判定依据】【结果】，
 * 使测试结论与失败原因一一可对照。
 */
public final class AuthTestLogger {

    private AuthTestLogger() {
    }

    public static Logger logger(Class<?> testClass) {
        return LoggerFactory.getLogger(testClass);
    }

    public static void input(Logger log, String template, Object... args) {
        log.info("[用例输入] " + template, args);
    }

    public static void basis(Logger log, String template, Object... args) {
        log.info("[判定依据] " + template, args);
    }

    public static void result(Logger log, String template, Object... args) {
        log.info("[用例结果] " + template, args);
    }
}
