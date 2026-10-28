package io.kepr;

/** Any failure talking to the daemon, or an error reply from it. */
public class KeprException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public KeprException(String message) {
        super(message);
    }

    public KeprException(String message, Throwable cause) {
        super(message, cause);
    }
}
