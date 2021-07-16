package org.uqbar.jwtexample.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.dao.RepoUsuario

@Service
class UsuarioService {
	@Autowired
	RepoUsuario repoUsuario
	def getAllUsers() {
		repoUsuario.allInstances
	}
	
}