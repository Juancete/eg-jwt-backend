package org.uqbar.jwtexample.controller

import java.time.LocalDateTime
import java.util.List
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.core.userdetails.User
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.uqbar.jwtexample.security.AuthorizationToken

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Dado un controller de usuario")
class UsuarioContrllerTest {
	@Autowired
	MockMvc mockMvc
	
	AuthorizationToken validAdminToken
	AuthorizationToken validUserToken
	AuthorizationToken invalidAdminToken
	
	@BeforeEach
	def void init(){
		validAdminToken = buildToken("administrador","aaaa",#["ROLE_ADMIN"])
		validUserToken = buildToken("user","aaaa",#["ROLE_USER"])
		val mocked = Mockito.mockStatic(AuthorizationToken)
		mocked.when([| AuthorizationToken.now()]).thenReturn(LocalDateTime.of(1990,08,19,10,35))
		invalidAdminToken = buildToken("administrador","aaaa",#["ROLE_ADMIN"])
	}
	
	@Test
	def void getUsersWithMockUserCustomAuthorities() {
		mockMvc
		.perform(MockMvcRequestBuilders.get("/usuarios")
		.contentType(MediaType.APPLICATION_JSON)
		.header(HttpHeaders.AUTHORIZATION,"Bearer " + validAdminToken))
		
		.andExpect(status.isOk)
		.andExpect(content.contentType(MediaType.APPLICATION_JSON))
		.andExpect(jsonPath("$.length()").value(2))
	}
	
	@Test
	def void getUsersWithInvalidMockUserCustomAuthorities() {
		mockMvc
		.perform(MockMvcRequestBuilders.get("/usuarios")
		.contentType(MediaType.APPLICATION_JSON)
		.header(HttpHeaders.AUTHORIZATION,"Bearer " + validUserToken))
		
		.andExpect(status.forbidden)
	}
	@Test
	def void getUsersWithExpiredToken() {
		mockMvc
		.perform(MockMvcRequestBuilders.get("/usuarios")
		.contentType(MediaType.APPLICATION_JSON)
		.header(HttpHeaders.AUTHORIZATION,"Bearer " + invalidAdminToken))
		
		.andExpect(status.unauthorized)
	}
	
	def buildToken(String username, String password, List<String> roles){
		AuthorizationToken.build(User
			.withUsername(username)
			.password(password)
			.authorities(AuthorizationToken.rolesToAuthority(roles))
			.accountExpired(false)
			.accountLocked(false)
			.credentialsExpired(false)
			.disabled(false)
			.build())		
	}
}