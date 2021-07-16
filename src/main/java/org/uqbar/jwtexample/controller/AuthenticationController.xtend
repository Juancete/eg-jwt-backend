package org.uqbar.jwtexample.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.uqbar.jwtexample.security.LoginRequest
import org.uqbar.jwtexample.security.TokenProvider
import org.uqbar.jwtexample.service.UserDetailService

@RestController
@CrossOrigin(origins="*")
class AuthenticationController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserDetailService usuarioService;

	@PostMapping("/login")
	def login(@RequestBody LoginRequest authenticationRequest) {			
		
		 val Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
			authenticationRequest.getUsername(), authenticationRequest.getPassword()))

		SecurityContextHolder.context.authentication = authentication
		val UserDetails userDetails = usuarioService.loadUserByUsername(authenticationRequest.getUsername())
		val String jwt = TokenProvider.generateToken(userDetails)

		return ResponseEntity.ok(jwt)
	}

}
