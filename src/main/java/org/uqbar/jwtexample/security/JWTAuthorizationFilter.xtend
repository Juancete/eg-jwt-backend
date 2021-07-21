package org.uqbar.jwtexample.security

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.SignatureException
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

import static extension org.uqbar.jwtexample.security.ResponseUtil.*

class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	
	new(AuthenticationManager authenticationManager) {
		super(authenticationManager)
	}

	override doFilterInternal(HttpServletRequest request, HttpServletResponse response
		,FilterChain chain)throws IOException, ServletException
	{
		try {
			val token = AuthorizationToken.build(request)
			
				val authentication = new UsernamePasswordAuthenticationToken(token.extractUsername, null, token.extractAuthorities)
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request))
				SecurityContextHolder.context.authentication = authentication
				chain.doFilter(request, response) 
		} catch (ExpiredJwtException e) {
			response.setResponseUnautorized(request,"Expired Token")
		} catch (SignatureException | UsernameNotFoundException e) {
			response.setResponseUnautorized(request,"Invalid Token")
		} catch (IOException e) {
			response.setResponseBadRequest(request, "Invalid data")
		} finally {
			SecurityContextHolder.clearContext()
		}
		
	}
}