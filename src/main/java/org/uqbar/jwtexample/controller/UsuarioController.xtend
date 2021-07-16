package org.uqbar.jwtexample.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.annotation.Secured
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import org.uqbar.jwtexample.security.TokenProvider
import org.uqbar.jwtexample.service.UsuarioService

@RestController
@CrossOrigin(origins="*")
class UsuarioController {
	
	@Autowired
	UsuarioService usuarioService
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/usuarios")
	def usuarios() {
		usuarioService.getAllUsers	
	}
	@Secured("ROLE_ADMIN","ROLE_USER")
	@GetMapping("/quiensoy")
	def quienSoy(@RequestHeader(name = "Authorization") String auth) {
		TokenProvider.extractUsername(auth.substring(7))	
	}
}
