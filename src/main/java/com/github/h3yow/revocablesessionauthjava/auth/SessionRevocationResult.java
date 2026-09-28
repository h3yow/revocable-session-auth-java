package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 对单条会话强制下线的结果。幂等可重复：
 * <ul>
 *   <li>会话不存在：found=false，revoked=false，重复调用结论一致；</li>
 *   <li>本次调用首次撤销：found=true, revoked=true, alreadyRevoked=false；</li>
 *   <li>会话此前已撤销（重复强制下线/用户已注销）：found=true, revoked=true, alreadyRevoked=true。</li>
 * </ul>
 */
public record SessionRevocationResult(
        String sessionId,
        boolean found,
        boolean revoked,
        boolean alreadyRevoked) {
}
