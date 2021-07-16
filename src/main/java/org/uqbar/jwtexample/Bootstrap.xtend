package org.uqbar.jwtexample

import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.dao.RepoUsuario
import org.uqbar.jwtexample.domain.Rol
import org.uqbar.jwtexample.domain.Usuario

@Service
class Bootstrap implements InitializingBean {
	@Autowired
	PasswordEncoder passwordEncoder
	
	@Autowired
	RepoUsuario repoUsuario
		
	override afterPropertiesSet() throws Exception {
		repoUsuario.create(new Usuario => [
			username = "Nico"
			password = passwordEncoder.encode("qwerty")
			habilitado = true
			roles = #[new Rol => [nombre = "ROLE_ADMIN" ],new Rol => [nombre = "ROLE_USER" ]]
		])
		repoUsuario.create(new Usuario => [
			username = "Ale"
			password = passwordEncoder.encode("1234")
			habilitado = true
			roles = #[new Rol => [nombre = "ROLE_USER" ]]
		])
	}
	
}