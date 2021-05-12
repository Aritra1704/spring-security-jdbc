package io.javabrains.springsecurityjdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;// Connect your datasource for JDBC configuration

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
        .dataSource(dataSource)// If any other db is used and that db provides its own datasource, inject that and use that over here
        // Use the same parameters for the below query
        .usersByUsernameQuery("select username, password, enabled"
            +" from users "
            +" where username = ?")
        .authoritiesByUsernameQuery("select username, authority "
            +" from authorities "
            +" where username = ?");

        /*Practice with default schema*/
//        .withDefaultSchema()
//        .withUser(
//                User.withUsername("user")
//                .password("password")
//                .roles("USER")
//        )
//        .withUser(
//                User.withUsername("admin")
//                        .password("password")
//                        .roles("ADMIN")
//        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasAnyRole("ADMIN")// Can be accessed only by admin role
                .antMatchers("/user").hasAnyRole("ADMIN", "USER")// Can be accessed either by admin or user role
                .antMatchers("/").permitAll()// Can be accessed by all
                .and().formLogin();// Provides a form login
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
