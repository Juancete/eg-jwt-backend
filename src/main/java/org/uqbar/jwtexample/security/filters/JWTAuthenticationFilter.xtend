package org.uqbar.jwtexample.security.filters

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.eclipse.xtend.lib.annotations.Accessors
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.uqbar.jwtexample.dao.RepoAuth
import org.uqbar.jwtexample.security.AuthorizationToken
import org.uqbar.jwtexample.security.RefreshToken
import org.uqbar.jwtexample.service.UserDetailService

import static extension org.uqbar.jwtexample.security.ResponseUtil.*

class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	RepoAuth repo
	
	UserDetailService userDetailService
	
	new(AuthenticationManager manager, UserDetailService _userDetailService,RepoAuth _repo ) {
		setAuthenticationFailureHandler(new JWTAuthenticationFailureHandler())
		authenticationManager = manager
		repo = _repo
		userDetailService = _userDetailService
	}
    
	override Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException 
	{
		var Authentication authentication = null
		try {
			val LoginRequest authenticationRequest = new ObjectMapper().readValue(request.inputStream,
				LoginRequest)
			authenticationRequest.validate
			authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))
			
		SecurityContextHolder.context.authentication = authentication
		
		} catch (IOException e) {
			response.setResponseBadRequest(request,"Invalid payload")
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
		val refreshToken = RefreshToken.build(userDetails)
		repo.add(usuario.username,refreshToken)
		response.setResponseLoginOk(accessToken,refreshToken)
	}
}

 class JWTAuthenticationFailureHandler implements AuthenticationFailureHandler {
		 
        
        override onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                throws IOException, ServletException {
            response.setResponseUnauthorized(request , "usuario o contraseña incorrecto")
        }
        
    }

@Accessors
class LoginRequest{
	String username
	String password
	
	def validate() {
		if (username === null || password === null)
			throw new IOException
	}
	
}