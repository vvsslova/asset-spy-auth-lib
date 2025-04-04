package asset.spy.auth.lib.exception;

import asset.spy.auth.lib.dto.ErrorResponseDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Order(1)
@Slf4j
public class LibraryExceptionHandler {

    @ExceptionHandler(JwtValidationException.class)
    private ResponseEntity<ErrorResponseDto> handleException(JwtValidationException e) {
        ErrorResponseDto response = new ErrorResponseDto(e.getMessage());
        log.error("Jwt validation exception: {}", e.getMessage(), e);
        return new ResponseEntity<ErrorResponseDto>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    private ResponseEntity<ErrorResponseDto> handleException(AccessDeniedException e) {
        ErrorResponseDto response = new ErrorResponseDto("Access denied");
        log.error("Access denied", e);
        return new ResponseEntity<ErrorResponseDto>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    private ResponseEntity<ErrorResponseDto> handleException(AuthenticationException e) {
        ErrorResponseDto response = new ErrorResponseDto(e.getMessage());
        log.error("Authentication exception", e);
        return new ResponseEntity<ErrorResponseDto>(response, HttpStatus.UNAUTHORIZED);
    }
}
