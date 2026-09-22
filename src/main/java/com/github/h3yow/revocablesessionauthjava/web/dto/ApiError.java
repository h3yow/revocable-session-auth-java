package com.github.h3yow.revocablesessionauthjava.web.dto;

/**
 * 对外统一错误体：只包含可区分的错误类别代码与安全提示，不暴露底层异常。
 */
public record ApiError(String error, String message) {
}
