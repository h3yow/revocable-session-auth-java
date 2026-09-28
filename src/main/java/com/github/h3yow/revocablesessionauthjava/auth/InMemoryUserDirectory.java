package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 内置两个演示账户（仅本地演示，密码明文存储，生产环境应使用加盐哈希）：
 * <ul>
 *   <li>alice / alice123 -> ROLE_USER</li>
 *   <li>admin / admin123 -> ROLE_ADMIN</li>
 * </ul>
 * 角色可由管理员通过 Web 接口调整，调整结果保留在内存目录中，影响后续重新登录。
 */
@Component
public class InMemoryUserDirectory implements UserDirectory {

    private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>(Map.of(
            "alice", new UserAccount("alice", "alice123", Set.of(Permissions.ROLE_USER)),
            "admin", new UserAccount("admin", "admin123", Set.of(Permissions.ROLE_ADMIN))));

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    @Override
    public boolean updateRoles(String username, Set<String> newRoles) {
        UserAccount existing = accounts.get(username);
        if (existing == null) {
            return false;
        }
        accounts.put(username, new UserAccount(existing.username(), existing.password(), Set.copyOf(newRoles)));
        return true;
    }
}
