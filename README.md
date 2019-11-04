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
### 2.Simple UserDetails and UserDetailsService ***(In this case roles as String)***


```java
public class MyUserDetails implements UserDetails {

    private String username;
    private String password;
    private boolean active;
    private List <GrantedAuthority> authorities;

    public MyUserDetails(User user){
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.active = user.isActive();
        this.authorities = Arrays.stream(user.getRoles().split(","))
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

   .
   .
   .
}
```

```java
@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);

        user.orElseThrow(()->new UsernameNotFoundException("Not found"+ username));

        return user.map(MyUserDetails::new).get();
    }
}
```
```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    MyUserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {//Authentication
        auth.userDetailsService(userDetailsService).passwordEncoder(getPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {//authorization
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("ADMIN","USER")
                .antMatchers("/").permitAll()
                .and().formLogin();

    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
}
```
