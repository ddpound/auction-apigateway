package com.example.auctionapigateway.erroradvice;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.ServletException;

@Log4j2
@ControllerAdvice
public class GlobalExceotionHandler {

    @ExceptionHandler(ServletException.class)
    public ResponseEntity<String> handleServletException(ServletException e) {
        // JWT 토큰 검증 실패시 실행될 예외 처리 로직
        // ...

        log.error(e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
    }

}
