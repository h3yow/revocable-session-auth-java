package com.github.h3yow.revocablesessionauthjava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 手工装配。
 *
 * <p>注入系统 UTC Clock，使令牌签发/过期判定统一基于同一时间源；
 * 测试中可用可控 Clock 替换以覆盖过期场景。
 */
@Configuration
public class AppBeans {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
