package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * 内置两个演示账户（仅本地演示，密码明文存储，生产环境应使用加盐哈希）：
 * <ul>
 *   <li>alice / alice123 -> ROLE_USER</li>
 *   <li>admin / admin123 -> ROLE_ADMIN</li>
 * </ul>
 */
@Component
public class InMemoryUserDirectory implements UserDirectory {

    private final Map<String, UserAccount> accounts = Map.of(
            "alice", new UserAccount("alice", "alice123", Set.of(Permissions.ROLE_USER)),
            "admin", new UserAccount("admin", "admin123", Set.of(Permissions.ROLE_ADMIN)));

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }
}
