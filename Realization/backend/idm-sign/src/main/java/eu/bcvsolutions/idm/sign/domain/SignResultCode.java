package eu.bcvsolutions.idm.sign.domain;

import org.springframework.http.HttpStatus;

import eu.bcvsolutions.idm.core.api.domain.ResultCode;

/**
 * Enum class for formatting response messages (mainly errors).
 * Every enum contains a string message and corresponding https HttpStatus code.
 *
 * Used http codes:
 * - 2xx - success
 * - 4xx - client errors (validations, conflicts ...)
 * - 5xx - server errors
 *
 * @author Roman Kucera
 */
public enum SignResultCode implements ResultCode {

	SIGN_CLIENT_ERROR(HttpStatus.BAD_REQUEST, "Example generated error [%s]");

	private final HttpStatus status;
	private final String message;

	private SignResultCode(HttpStatus status, String message) {
		this.message = message;
		this.status = status;
	}

	public String getCode() {
		return this.name();
	}
	
	public String getModule() {
		return "sign";
	}

	public HttpStatus getStatus() {
		return status;
	}

	public String getMessage() {
		return message;
	}
}
