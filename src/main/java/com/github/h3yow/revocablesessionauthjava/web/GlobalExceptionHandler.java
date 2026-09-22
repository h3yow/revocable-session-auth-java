package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.domain.AuthException;
import com.github.h3yow.revocablesessionauthjava.domain.TokenError;
import com.github.h3yow.revocablesessionauthjava.web.dto.ApiError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理：
 * <ul>
 *   <li>领域失败 → 按 TokenError 映射状态码与可区分错误码，仅返回安全提示；</li>
 *   <li>请求体非法等 → 统一归入 BAD_CREDENTIALS/MISSING_TOKEN 级别泛化错误；</li>
 *   <li>底层异常详情只记录在服务端日志，不回传调用方。</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiError> handleAuth(AuthException ex) {
        TokenError error = ex.error();
        log.warn("请求被拒绝 类别={} httpStatus={}", error.name(), error.httpStatus());
        return ResponseEntity.status(error.httpStatus())
                .body(new ApiError(error.name(), error.publicMessage()));
    }

    /** JSON 缺失 / 无法解析：不暴露解析器细节。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        log.debug("请求体无法解析（细节仅服务端可见）: {}", ex.getMessage());
        return ResponseEntity.status(400)
                .body(new ApiError("MALFORMED_REQUEST", "请求体格式不正确或缺少必要字段"));
    }

    /** 非法入参（如未知角色名）：泛化为请求格式问题。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgument(IllegalArgumentException ex) {
        log.debug("非法请求参数（细节仅服务端可见）: {}", ex.getMessage());
        return ResponseEntity.status(400)
                .body(new ApiError("MALFORMED_REQUEST", "请求参数不合法"));
    }

    /** 兜底：任何未预期异常都不把堆栈/内部信息暴露给调用方。 */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception ex) {
        log.error("未预期异常（细节仅服务端可见）", ex);
        return ResponseEntity.status(500)
                .body(new ApiError("INTERNAL_ERROR", "服务内部错误"));
    }
}
