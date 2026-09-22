package com.github.h3yow.revocablesessionauthjava.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** 测试配置：用 {@link MutableClock} 替换生产时钟（它本身就是 Clock，一个 Bean 即可）。 */
@TestConfiguration
public class TestClockConfig {

    @Bean
    @Primary
    public MutableClock mutableClock() {
        return new MutableClock();
    }
}
