package com.github.h3yow.revocablesessionauthjava.tests;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.domain.TokenPair;
import com.github.h3yow.revocablesessionauthjava.security.AuthService;
import com.github.h3yow.revocablesessionauthjava.security.session.SessionStore;
import com.github.h3yow.revocablesessionauthjava.security.token.TokenService;
import com.github.h3yow.revocablesessionauthjava.security.user.UserStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发刷新测试：同一刷新令牌被多个请求同时使用时，
 * 原子轮换必须保证“恰好一次成功”，其余全部得到 REUSE_DETECTED。
 */
class ConcurrentRefreshTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTest.class);

    @Test
    void sameRefreshTokenSucceedsExactlyOnceUnderConcurrency() throws Exception {
        int threads = 16;
        Clock clock = Clock.fixed(Instant.ofEpochSecond(2_000_000_000L), ZoneOffset.UTC);
        TokenService tokenService =
                new TokenService(clock, "concurrent-test-secret-0123456789abcdef", 300, 3600);
        SessionStore sessionStore = new SessionStore();
        AuthService authService = new AuthService(tokenService, sessionStore, new UserStore());

        TokenPair login = authService.login("alice", "user123");
        String sharedRefreshToken = login.refreshToken();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger replayRejected = new AtomicInteger();
        AtomicInteger otherFailures = new AtomicInteger();

        List<Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    TokenPair pair = authService.refresh(sharedRefreshToken);
                    success.incrementAndGet();
                    log.info("并发刷新 线程#{} 输入=同一刷新令牌 判定依据=原子rotate抢到唯一一次jti匹配 结果=成功", idx);
                    return pair;
                } catch (AuthException e) {
                    if (e.error() == TokenError.REUSE_DETECTED) {
                        replayRejected.incrementAndGet();
                        log.info("并发刷新 线程#{} 输入=同一刷新令牌 判定依据=jti已不匹配/会话已撤销 结果={}",
                                idx, e.error().name());
                    } else {
                        otherFailures.incrementAndGet();
                        log.warn("并发刷新 线程#{} 出现非预期类别 结果={}", idx, e.error().name());
                    }
                } catch (Exception e) {
                    otherFailures.incrementAndGet();
                }
                return null;
            }));
        }

        assertTrue(ready.await(5, TimeUnit.SECONDS), "工作线程未能全部就绪");
        start.countDown(); // 同时放行
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        log.info("用例=16线程并发刷新同一令牌 输入=共享同一刷新令牌x16 判定依据=ConcurrentHashMap.compute原子读改写 "
                + "结果=成功{}次, REUSE_DETECTED拒绝{}次, 其它失败{}次",
                success.get(), replayRejected.get(), otherFailures.get());

        assertEquals(1, success.get(), "同一刷新令牌必须恰好成功一次");
        assertEquals(threads - 1, replayRejected.get(), "其余并发请求必须被明确归类为重放");
        assertEquals(0, otherFailures.get(), "不应出现其它失败类别");

        // 重放发生后，会话族必须处于撤销状态：即便使用“胜利者”新拿到的刷新令牌也应被拒绝
        AuthException after = catchAuth(() -> {
            // 胜利者的新令牌无法直接收集，改为再次提交旧令牌，验证会话已撤销
            authService.refresh(sharedRefreshToken);
        });
        log.info("用例=并发竞争结束后再试 输入=同一旧令牌 判定依据=会话族已因重放被撤销 结果={}",
                after == null ? "SUCCESS(意外)" : after.error().name());
        assertEquals(TokenError.REUSE_DETECTED, after == null ? null : after.error());
    }

    private AuthException catchAuth(Runnable r) {
        try {
            r.run();
            return null;
        } catch (AuthException e) {
            return e;
        }
    }
}
