package org.uqbar.jwtexample.security.filters

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.SignatureException
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.eclipse.xtend.lib.annotations.Accessors
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.uqbar.jwtexample.dao.RepoAuth
import org.uqbar.jwtexample.security.AuthorizationToken
import org.uqbar.jwtexample.security.RefreshToken
import org.uqbar.jwtexample.security.RefreshTokenAuthenticationToken
import org.uqbar.jwtexample.security.Token
import org.uqbar.jwtexample.service.UserDetailService

import static extension org.uqbar.jwtexample.security.ResponseUtil.*

class JWTRefreshFilter extends AbstractAuthenticationProcessingFilter {
	RepoAuth repo
	UserDetailService userDetailService
	Token refreshToken
	UserDetails userDetails
	
	new(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager, UserDetailService _userDetailService, RepoAuth _repo) {
		super(defaultFilterProcessesUrl, authenticationManager)
		userDetailService = _userDetailService
		repo = _repo
	}

	override attemptAuthentication(HttpServletRequest request,
		HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		var Authentication authentication = null
		try {
			val RefreshTokenRequest authenticationRequest = new ObjectMapper().readValue(request.inputStream,
				RefreshTokenRequest)

			refreshToken = RefreshToken.build(authenticationRequest.refreshToken)
			if (!repo.verifyToken(refreshToken.extractUsername,refreshToken))
				response.setResponseUnauthorized(request, "Invalid Token")
			else if (SecurityContextHolder.context.authentication === null) {
				userDetails = userDetailService.loadUserByUsername(refreshToken.extractUsername)
				
				authentication = new RefreshTokenAuthenticationToken(userDetails, userDetails.authorities)

				SecurityContextHolder.context.authentication = authentication
			} 

		} catch (ExpiredJwtException e) {
			response.setResponseUnauthorized(request, "Expired Token")

		} catch (SignatureException | UsernameNotFoundException e) {
			response.setResponseUnauthorized(request,"Invalid Token")
			
		} catch (IOException e) {
			SecurityContextHolder.clearContext()
			response.setResponseBadRequest(request, "Invalid data")
		} finally {
			SecurityContextHolder.clearContext()
		}
		authentication
	}
	
	    override successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authenticationRequest) throws IOException, ServletException {
	
		val usuario = authenticationRequest.principal as User
		val UserDetails userDetails = userDetailService.loadUserByUsername(usuario.username)
		val accessToken = AuthorizationToken.build(userDetails)
		response.setResponseLoginOk(accessToken,refreshToken)
	}

}

@Accessors
class RefreshTokenRequest {
	String refreshToken
}
