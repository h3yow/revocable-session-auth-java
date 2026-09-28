package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;

/**
 * 内置两个演示账户（仅本地演示，密码明文存储，生产环境应使用加盐哈希）：
 * <ul>
 *   <li>alice / alice123 -> ROLE_USER</li>
 *   <li>admin / admin123 -> ROLE_ADMIN</li>
 * </ul>
 * 角色可被管理员接口更新，使用并发容器保证读写安全。
 */
@Component
public class InMemoryUserDirectory implements UserDirectory {

    private final ConcurrentMap<String, UserAccount> accounts = new ConcurrentHashMap<>();

    public InMemoryUserDirectory() {
        accounts.put("alice", new UserAccount("alice", "alice123", Set.of(Permissions.ROLE_USER)));
        accounts.put("admin", new UserAccount("admin", "admin123", Set.of(Permissions.ROLE_ADMIN)));
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    @Override
    public boolean updateRoles(String username, Set<String> newRoles) {
        Set<String> safeRoles = newRoles == null ? Set.of() : Set.copyOf(newRoles);
        return accounts.computeIfPresent(username, (name, account) ->
                new UserAccount(account.username(), account.password(), safeRoles)) != null;
    }
}
