package org.uqbar.jwtexample.security

import io.jsonwebtoken.ExpiredJwtException
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component("jwtRequestFilter")
class JwtRequestFilter extends OncePerRequestFilter {

	override protected doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain chain) throws ServletException, IOException {
		try {
			val token = Token.generateTokenFromHeader(request)

			if (SecurityContextHolder.context.authentication === null) {
				val authentication = new UsernamePasswordAuthenticationToken(token.extractUsername, null, token.extractAuthorities)
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request))
				SecurityContextHolder.context.authentication = authentication
			}

		} catch (ExpiredJwtException e) {
			val texto = 
			'''{"error": "Unautorized"
				"message": "Expired Token"
				"path": "«request.getRequestURL()»"
				}'''
			response.setContentType("application/json")
			response.status = HttpServletResponse.SC_UNAUTHORIZED
			response.getWriter().write(texto)
			return
		} 

		chain.doFilter(request, response)
	}
}
