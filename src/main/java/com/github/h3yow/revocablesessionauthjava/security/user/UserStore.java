package com.github.h3yow.revocablesessionauthjava.security.user;

import com.github.h3yow.revocablesessionauthjava.domain.Role;
import com.github.h3yow.revocablesessionauthjava.domain.User;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户存储（本地内存实现）。
 *
 * <p>内置演示用户：alice/user123（普通角色）、admin/admin123（管理员角色）。
 * 角色变更以不可变整体对象替换写回，保证并发读取始终拿到一致快照。
 * 密码以 随机盐 + SHA-256 摘要存储（本地演示用途，不用于生产强度评估）。
 */
@Component
public class UserStore {

    /** 内存用户记录：盐 + 密码摘要。 */
    private record StoredCredential(String salt, String hash) {
    }

    private final ConcurrentHashMap<String, User> usersById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> usernameToId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, StoredCredential> credentials = new ConcurrentHashMap<>();

    public UserStore() {
        seed("u-alice", "alice", "user123", Set.of(Role.USER));
        seed("u-admin", "admin", "admin123", Set.of(Role.USER, Role.ADMIN));
    }

    private void seed(String id, String username, String password, Set<Role> roles) {
        String salt = "salt-" + username;
        usersById.put(id, new User(id, username, null, true, roles));
        usernameToId.put(username, id);
        credentials.put(id, new StoredCredential(salt, sha256(salt + password)));
    }

    public User findByUsername(String username) {
        if (username == null) {
            return null;
        }
        String id = usernameToId.get(username);
        return id == null ? null : usersById.get(id);
    }

    public User findById(String userId) {
        return usersById.get(userId);
    }

    /** 校验明文密码；用户不存在或密码不匹配均返回 false（由上层统一归为 BAD_CREDENTIALS）。 */
    public boolean verifyPassword(User user, String rawPassword) {
        if (user == null || rawPassword == null) {
            return false;
        }
        StoredCredential credential = credentials.get(user.id());
        if (credential == null) {
            return false;
        }
        return MessageDigest.isEqual(
                credential.hash().getBytes(StandardCharsets.UTF_8),
                sha256(credential.salt() + rawPassword).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 原子替换角色集合，返回新的用户快照；用户不存在时返回 null。
     * 权限判定时实时读取该快照，因此角色变更对已签发的访问令牌立即生效。
     */
    public User replaceRoles(String userId, Set<Role> roles) {
        final User[] result = new User[1];
        usersById.computeIfPresent(userId, (id, current) -> {
            User updated = new User(current.id(), current.username(), current.passwordHash(),
                    current.enabled(), Set.copyOf(roles));
            result[0] = updated;
            return updated;
        });
        return result[0];
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("password hashing failed");
        }
    }
}
