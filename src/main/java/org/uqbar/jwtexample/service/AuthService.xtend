package org.uqbar.jwtexample.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.security.LoginRequest
import org.uqbar.jwtexample.security.TokenProvider

@Service
class AuthService {
	@Autowired
	UserDetailService userDetailService

	@Autowired
	AuthenticationManager authenticationManager

	def authenticate(LoginRequest authenticationRequest) {
		val Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))

		SecurityContextHolder.context.authentication = authentication
		val UserDetails userDetails = userDetailService.loadUserByUsername(authenticationRequest.getUsername())
		val String jwt = TokenProvider.generateToken(userDetails)
		'''{"token": "«jwt»"
				"refreshToken": "Expired Token"
				}'''
	}
}
