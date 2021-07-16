package org.uqbar.jwtexample.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.dao.RepoUsuario
import org.uqbar.jwtexample.domain.Usuario
import org.uqbar.jwtexample.security.TokenProvider

@Service
class UserDetailService implements UserDetailsService {

	@Autowired
	RepoUsuario userRepository

	override UserDetails loadUserByUsername(String username) {
		val Usuario user = userRepository.findByName(username)
		if (user === null) {
			throw new UsernameNotFoundException(username)
		}
		val authorities = TokenProvider.rolesToAuthority(user.getRoles().map [ role |
			role.nombre
		])
		User.withUsername(username).password(user.password).authorities(authorities).accountExpired(false).
			accountLocked(false).credentialsExpired(false).disabled(false).build()
	}
}
