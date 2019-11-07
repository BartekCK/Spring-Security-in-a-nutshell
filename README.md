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

### 3.Add Bcrypt and PreAuthorize

```java
@RestController
public class HomeController {

    @GetMapping("/")
    public String home(){
        return "Hello World!!!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String user(){
        return "Hello USER";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String admin(){
        return "Hello ADMIN";
    }
}
```
**Change in ***public class SecurityConfiguration extends WebSecurityConfigurerAdapter*****
```java
   @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
```

### 4.Roles, authorities and simple User in memory

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode("admin"))
                    .roles("ADMIN").authorities("ACCESS_TEST1","ACCESS_TEST2")
                .and()
                .withUser("dan").password(passwordEncoder().encode("dan"))
                    .roles("USER")
                .and()
                .withUser("manager").password(passwordEncoder().encode("manager"))
                    .roles("MANAGER").authorities("ACCESS_TEST1");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                 .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
```
### 5.Add database provider **(Better way is use only ***auth.userDetailsService(userDetailsService).passwordEncoder(getPasswordEncoder());***)**

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserPrincipalDetailsService userPrincipalDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                 .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);
        return  daoAuthenticationProvider;
    }
}
```

**Static database**
```java
@Service
public class DbInit implements CommandLineRunner {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    public DbInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        userRepository.deleteAll();

        User dan = new User("dan",passwordEncoder.encode("dan"),"ROLE_USER","");
        User admin = new User("admin",passwordEncoder.encode("admin"),"ROLE_ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager",passwordEncoder.encode("manager"),"ROLE_MANAGER","ACCESS_TEST1");

        List<User> users = Arrays.asList(dan,admin,manager);
        this.userRepository.saveAll(users);
    }
}
```

```java
public class UserPrincipal implements UserDetails {

    private User user;
    private List<GrantedAuthority> authorities;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {


        this.authorities = user.getRoleList().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        this.authorities.addAll(user.getPermissionList().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

        return this.authorities;
    }
```

```java
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    private String roles;

    private String permissions;

    //etc...........
    //..............

    public List<String> getRoleList(){
        if(this.roles.length()>0)
            return Arrays.asList(this.roles.split(","));
        return new ArrayList<>();
    }

    public List<String> getPermissionList(){
        if(this.roles.length()>0)
            return Arrays.asList(this.permissions.split(","));
        return new ArrayList<>();
    }
}
```

### 6. Own login page manage by Security ***(Using MVC)***

```java
//...
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                 .and()
                .formLogin()
                .loginPage("/login").permitAll();
    }
```

```java
@Controller
@RequestMapping("/")
public class HomeController {
    @GetMapping("index")
    public String index(){
        return "index";
    }

    @GetMapping("login")
    public String login(){
        return "login";
    }
}
```

```html
<div class="container">
    <div style="width:600px;margin-left: auto;margin-right: auto;margin-top:24px;padding: 24px;">
        <div class="card">
            <div class="card-header">
                <i class="fa fa-user"></i> Please Login
            </div>
            <div class="card-block" style="padding: 24px;">
                <form name="f" th:action="@{/login}" method="post">
                    <fieldset>
                        <!-- Thymeleaf + Spring Security error display -->
                        <div th:if="${param.error}" class="alert alert-danger">
                            Invalid username and password.
                        </div>

                        <div th:if="${param.logout}" class="alert alert-success">
                            You have been logged out.
                        </div>

                        <!-- Login Controls -->
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" class="form-control" id="username" name="username"
                                   placeholder="Username">
                        </div>

                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" class="form-control" id="password" name="password"
                                   placeholder="Password">
                        </div>

                        <div class="form-check">
                            <input type="checkbox" class="form-check-input" id="checkRememberMe" name="checkRememberMe">
                            <label class="form-check-label" for="checkRememberMe">Remember me?</label>
                        </div>

                        <!-- Login Button -->
                        <div class="form-actions" style="margin-top: 12px;">
                            <button type="submit" class="btn btn-success">Log in</button>
                        </div>
                    </fieldset>
                </form>
            </div>
        </div>
    </div>
</div>
```
