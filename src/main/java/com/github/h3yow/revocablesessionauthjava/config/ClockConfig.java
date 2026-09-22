package com.github.h3yow.revocablesessionauthjava.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 提供系统 UTC 时钟；测试中可替换为固定/可调时钟以验证过期场景。 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
