package org.uqbar.jwtexample.security

import java.util.Date
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ResponseUtil {

	def private static setResponseError(HttpServletResponse response, HttpServletRequest request, String message,
		int status) {
		
		val texto = '''{"timestamp":"«new Date().time»"
				"message": "«message»"
				"path": "«request.getRequestURL()»"
				}'''
		response.contentType = "application/json"
		response.status = status
		response.getWriter().write(texto)
	}

	def static setResponseBadRequest(HttpServletResponse response, HttpServletRequest request, String message) {
		setResponseError(response, request, message, HttpServletResponse.SC_BAD_REQUEST)
	}

	def static setResponseUnautorized(HttpServletResponse response, HttpServletRequest request, String message) {
		setResponseError(response, request, message, HttpServletResponse.SC_UNAUTHORIZED)
	}

	def static setResponseLoginOk(HttpServletResponse response, Token accessToken, Token refreshToken) {
		val body = '''{"token": "«accessToken»",
				"refreshToken": "«refreshToken»"
				}'''
		response.contentType = "application/json"
		response.getWriter().append(body)
	}
}
