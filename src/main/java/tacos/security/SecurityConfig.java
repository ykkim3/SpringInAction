package tacos.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
		.authorizeRequests()
		.antMatchers("/design", "/orders")
		.access("hasRole('ROLE_USER')")
		.antMatchers("/","/**").access("permitAll")
		.and()
		.httpBasic();
	}

	/*
	 * inmemory store
	 */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
//		.withUser("user1")
//		.password("{noop}password1")
//		.authorities("ROLE_USER")
//		.and()
//		.withUser("user2")
//		.password("{noop}password2")
//		.authorities("ROLE_USER");
//	}

	/*
	 * jdbc store
	 */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.jdbcAuthentication().dataSource(dataSource)
//		.usersByUsernameQuery("select username, password, enabled from users where username=?")
//		.authoritiesByUsernameQuery("select username, authority from authorities where username=?")
//		.passwordEncoder(new NoEncodingPasswordEndoder());
//	}
	
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth
//		.ldapAuthentication()
//		.userSearchBase("ou=people")
//		.userSearchFilter("(uid={0})")
//		.groupSearchBase("ou=groups")
//		.groupSearchFilter("member={0}")
//		.contextSource()
////		.root("dc=tacocloud,dc=com")
////		.ldif("classpath:users.ldif")
//		.url("ldap://localhost:8389/dc=tacocloud,dc=com")
//		.and()
//		.passwordCompare()
////		.passwordEncoder(new BCryptPasswordEncoder())
//		.passwordEncoder(new NoEncodingPasswordEndoder())
//		.passwordAttribute("userPasscode");
//	}
//	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.userDetailsService(userDetailsService)
			.passwordEncoder(encoder());
	}
}
