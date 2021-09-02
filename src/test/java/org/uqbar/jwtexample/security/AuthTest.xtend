package org.uqbar.jwtexample.security

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.uqbar.jwtexample.dao.RepoUsuario
import org.junit.jupiter.api.BeforeEach
import org.uqbar.jwtexample.domain.Usuario
import org.uqbar.jwtexample.domain.Rol
import org.springframework.security.crypto.password.PasswordEncoder

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Dado un controller de autenticación")
class AuthTest {
	
	@Autowired
	PasswordEncoder passwordEncoder
	
	@Autowired
	MockMvc mockMvc
	
	@Autowired
	RepoUsuario repoUsuario
	
	@BeforeEach
	def void init() {
		repoUsuario => [
			objects.clear
			create(new Usuario() => [
				username = "Nico"
				password = passwordEncoder.encode("qwerty")
				roles = #[new Rol()=>[nombre = "ROLE_ADMIN"],new Rol()=>[nombre = "ROLE_USER"]]
			])
		]
	}
	
	@Test
	@DisplayName("loguearse con credenciales válidas retorna el token de acceso y el de refresh")
	def void logueoExitoso() {
		mockMvc
		.perform(MockMvcRequestBuilders.post("/login")
		.contentType(MediaType.APPLICATION_JSON)
		.content('''{
			"username":"Nico",
			"password":"qwerty"
			}'''))
		.andExpect(status.isOk)
		.andExpect(content.contentType(MediaType.APPLICATION_JSON))
		.andExpect(jsonPath("$.token").exists)
		.andExpect(jsonPath("$.refreshToken").exists)
	}
	@Test
	@DisplayName("intentar loguearse con payload invalido, devuelve 400")
	def void logueoSinPayload() {
		mockMvc
		.perform(
			MockMvcRequestBuilders.post("/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content('{}')
		)
		.andExpect(status.badRequest)
	}
	
	@Test
	@DisplayName("intentar loguearse con usuario incorrecto, devuelve 401")
	def void logueoCredencialesIncorrectas() {
		mockMvc
		.perform(
			MockMvcRequestBuilders.post("/login")
			.contentType(MediaType.APPLICATION_JSON)
		.content('''{
			"username":"Nicola",
			"password":"qwerty"
			}'''))
		
		.andExpect(status.unauthorized)
	}

	@Test
	@DisplayName("intentar loguearse con usuario incorrecto, devuelve 400")
	def void logueoIncorrecto() {
		mockMvc
		.perform(
			MockMvcRequestBuilders.post("/login")
			.contentType(MediaType.APPLICATION_JSON)
		.content('''{
			}'''))
		
		.andExpect(status.badRequest)
	}	
}