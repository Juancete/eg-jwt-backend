package org.uqbar.jwtexample.dao

import org.apache.commons.collections15.Predicate
import org.springframework.stereotype.Repository
import org.uqbar.commons.model.CollectionBasedRepo
import org.uqbar.jwtexample.domain.Usuario

@Repository
class RepoUsuario extends CollectionBasedRepo<Usuario> {

	override protected getCriterio(Usuario example) {
		new Predicate<Usuario> {
			override evaluate(Usuario usuario) {
				example.username === null || example.password === null ||
					(usuario?.username.toUpperCase.contains(example.username?.toUpperCase) &&
						usuario?.password.toUpperCase.contains(example.password?.toUpperCase)
					)
			}
		}
	}

	
	override createExample() {
		new Usuario
	}

	override getEntityType() {
		Usuario
	}
	
	def findByName(String nombre) {
		this.allInstances.filter[user | user.username == nombre].head
	}

}
