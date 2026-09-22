package com.github.h3yow.revocablesessionauthjava.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 测试用可控时钟：从固定基准时间起步，advanceMillis 后所有读取者立即看到新时间。
 * 替换 Spring 容器中的 Clock Bean，使令牌过期场景可确定性复现。
 */
public class MutableClock extends Clock {

    private volatile Instant now;

    public MutableClock() {
        this.now = Instant.parse("2026-09-22T00:00:00Z");
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now;
    }

    public void advance(Duration duration) {
        this.now = now.plus(duration);
    }
}
