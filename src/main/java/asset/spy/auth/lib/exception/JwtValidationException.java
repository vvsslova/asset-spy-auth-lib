package asset.spy.auth.lib.exception;

import io.jsonwebtoken.JwtException;

public class JwtValidationException extends JwtException {
    public JwtValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
