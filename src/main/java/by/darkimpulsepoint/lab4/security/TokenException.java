package by.darkimpulsepoint.lab4.security;

import lombok.Getter;

@Getter
public class TokenException extends RuntimeException {

    public enum Code {
        TOKEN_MISSING,
        TOKEN_MALFORMED,
        ALGORITHM_NOT_ALLOWED,
        INVALID_SIGNATURE,
        INVALID_CLAIMS,
        WRONG_TOKEN_TYPE,
        TOKEN_EXPIRED
    }

    private final Code code;

    public TokenException(Code code, String message) {
        super(message);
        this.code = code;
    }
}
