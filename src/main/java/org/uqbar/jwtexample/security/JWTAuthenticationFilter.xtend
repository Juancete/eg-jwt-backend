package org.uqbar.jwtexample.security

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException
import java.util.Date
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.uqbar.jwtexample.service.UserDetailService

class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	UserDetailService userDetailService
	
	new(AuthenticationManager manager, UserDetailService _userDetailService) {
		setAuthenticationFailureHandler(new JWTAuthenticationFailureHandler())
		authenticationManager = manager
		userDetailService = _userDetailService
	}
    
	override Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException 
	{
		try {
			val LoginRequest authenticationRequest = new ObjectMapper().readValue(request.getInputStream(),
				LoginRequest)

			val Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))
			
		
		SecurityContextHolder.context.authentication = authentication
		authentication
		} catch (IOException e) {
			throw new RuntimeException(e)
		}
	}
	
    override successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authenticationRequest) throws IOException, ServletException {
	
		val usuario = authenticationRequest.principal as User
		val UserDetails userDetails = userDetailService.loadUserByUsername(usuario.username)
		val String accessToken = Token.generateAccessToken(userDetails).toString
		val String refreshToken = Token.generateRefreshToken(userDetails).toString
		val body ='''{"token": "«accessToken»",
				"refreshToken": "«refreshToken»"
				}'''
        response.addHeader("Authorization", "Bearer " + accessToken)
        response.addHeader("access-control-expose-headers", "Authorization")
        response.contentType = "application/json"
        response.getWriter().append(body)
	}
}

 class JWTAuthenticationFailureHandler implements AuthenticationFailureHandler {
		 
        
        override onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                throws IOException, ServletException {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.contentType = "application/json"
            val json = '''{"timestamp":"«new Date().getTime()»",
				"error": "Unautorized",
				"message": "usuario o contraseña incorrecto",
				"path": "«request.getRequestURL()»"
				}'''
            response.getWriter().append(json)
        }
        
    }