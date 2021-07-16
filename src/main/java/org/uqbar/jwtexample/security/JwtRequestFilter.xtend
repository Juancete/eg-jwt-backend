package org.uqbar.jwtexample.security

import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import org.uqbar.jwtexample.service.UserDetailService

@Component("jwtRequestFilter")
class JwtRequestFilter extends OncePerRequestFilter {
	@Autowired
	UserDetailService usuarioService;

	override protected doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain chain) throws ServletException, IOException {
		
		var String username = null
		var String jwt = null
		if (TokenProvider.isValidHeader(request)) {
			jwt = TokenProvider.getTokenFromHeader(request)
			username = TokenProvider.extractUsername(jwt)
		}

		if (username !== null && SecurityContextHolder.context.authentication === null) {

			val userDetails = usuarioService.loadUserByUsername(username)

			if (TokenProvider.validateToken(jwt, userDetails)) {

				val authentication = new UsernamePasswordAuthenticationToken(
					userDetails, null, userDetails.getAuthorities())
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request))
				SecurityContextHolder.context.authentication = authentication
			}
		}

		chain.doFilter(request, response)
	}
}
