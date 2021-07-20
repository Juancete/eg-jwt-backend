package org.uqbar.jwtexample.controller

import javax.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.annotation.Secured
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.uqbar.jwtexample.security.Token
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
	def quienSoy(HttpServletRequest request, Model model) {
		val token = Token.generateTokenFromHeader(request)
		token.extractUsername
	}
}
