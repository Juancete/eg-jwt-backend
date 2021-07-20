package org.uqbar.jwtexample.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.uqbar.jwtexample.security.LoginRequest
import org.uqbar.jwtexample.service.AuthService

@RestController
@CrossOrigin(origins="*")
class AuthenticationController {
	
	@Autowired
	AuthService authService

	@PostMapping("/login")
	def login(@RequestBody LoginRequest authenticationRequest) {			
		val response = authService.authenticate(authenticationRequest)
		ResponseEntity.ok(response)
	}

}
