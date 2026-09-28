package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.auth.AuthException;
import com.github.h3yow.revocablesessionauthjava.auth.AuthFailureReason;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理。对外响应体只含稳定 error code 与固定中文描述，
 * 底层异常细节（堆栈、算法信息、内部标识拼串）只写服务端日志。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** 鉴权/治理类失败：HTTP 状态由 {@link AuthFailureReason#httpStatus()} 决定。 */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, String>> handleAuth(AuthException ex) {
        AuthFailureReason reason = ex.reason();
        // internalDetail 仅进入日志，不返回给调用方
        log.warn("鉴权失败 reason={} internalDetail={}", reason.code(), ex.internalDetail());
        return ResponseEntity.status(reason.httpStatus())
                .body(Map.of("error", reason.code(), "message", reason.description()));
    }

    /** 请求体无法解析：归类为 malformed_token 不适用，这里返回参数格式错误但不泄露解析细节。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleUnreadable(HttpMessageNotReadableException ex) {
        log.warn("请求体无法解析: {}", ex.getClass().getSimpleName());
        return ResponseEntity.badRequest()
                .body(Map.of("error", "malformed_request", "message", "请求体格式不合法"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleOther(Exception ex) {
        log.error("未预期的服务端异常", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "internal_error", "message", "服务内部错误"));
    }
}
