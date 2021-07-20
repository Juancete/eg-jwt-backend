package org.uqbar.jwtexample.security

import io.jsonwebtoken.ExpiredJwtException
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	
	new(AuthenticationManager authenticationManager) {
		super(authenticationManager)
	}

	override doFilterInternal(HttpServletRequest request, HttpServletResponse response
		,FilterChain chain)throws IOException, ServletException
	{
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