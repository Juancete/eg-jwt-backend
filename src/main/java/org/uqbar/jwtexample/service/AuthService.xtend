package org.uqbar.jwtexample.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.security.LoginRequest
import org.uqbar.jwtexample.security.Token

@Service
class AuthService {
	@Autowired
	UserDetailService userDetailService

	@Autowired
	AuthenticationManager authenticationManager

	@Deprecated
	def authenticate(LoginRequest authenticationRequest) {
		val Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))

		SecurityContextHolder.context.authentication = authentication

		val UserDetails userDetails = userDetailService.loadUserByUsername(authenticationRequest.getUsername())
		val String accessToken = Token.generateAccessToken(userDetails).toString
		val String refreshToken = Token.generateRefreshToken(userDetails).toString
		'''{"token": "«accessToken»"
				"refreshToken": "«refreshToken»"
				}'''
	}

	def attemptLogin(LoginRequest authenticationRequest) {
		authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))
	}
}
