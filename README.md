# Spring Security in a nutshell

### 1.Common configuration without database and passwordEncoder ***(not recommended)***

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("moderator")
                .build();


        UserDetails userDetails2 = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("admin")
                .build();

        return new InMemoryUserDetailsManager(userDetails,userDetails2);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {//zajmuje sie konfiguracja dostepu 
       http.csrf().disable()//Desable CSRF
               .httpBasic().and()//Basic SignIn
               .authorizeRequests()
               .antMatchers(HttpMethod.GET,"/api").permitAll()
               .antMatchers(HttpMethod.POST,"/api").hasRole("moderator")
               .antMatchers(HttpMethod.DELETE,"/api").hasRole("admin")
               .anyRequest().hasRole("admin")
               .and()
               .formLogin().permitAll()
               .and()
               .logout().permitAll();
    }
}
```
