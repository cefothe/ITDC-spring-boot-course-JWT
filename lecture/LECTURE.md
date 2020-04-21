# JWT and Spring Boot

## What is JWT
JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for 
securely transmitting information between parties as a JSON object. This information can be verified 
and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) 
or a public/private key pair using RSA or ECDSA.

## When should you use JSON Web Tokens? 
1. Authorization
2. Information Exchange

## What is the JSON Web Token structure?
In its compact form, JSON Web Tokens consist of three parts separated by dots (.), which are:
1. Header
The header typically consists of two parts: the type of the token, which is JWT, 
and the signing algorithm being used, such as HMAC SHA256 or RSA.
    ```
    {
      "alg": "HS256",
      "typ": "JWT"
    }
    ```
2.  Payload
    ```
    {
      "sub": "1234567890",
      "name": "John Doe",
      "admin": true
    }
    ```
3.  Signature
    ```
    HMACSHA256(
      base64UrlEncode(header) + "." +
      base64UrlEncode(payload),
      secret)
    ```
    
Therefore, a JWT typically looks like the following.

```
xxxxx.yyyyy.zzzzz
```

## How do JSON Web Tokens work?
In authentication, when the user successfully logs in using their credentials, 
a JSON Web Token will be returned. Since tokens are credentials, 
great care must be taken to prevent security issues. 
In general, you should not keep tokens longer than required.

Whenever the user wants to access a protected route or resource, 
the user agent should send the JWT, typically in the Authorization header 
using the Bearer schema. The content of the header should look like the following:

```
Authorization: Bearer <token>
```

## Authentication vs Authorization

### Authentication
Authentication is about validating your credentials such as Username/User ID 
and password to verify your identity. The system then checks whether you are 
what you say you are using your credentials. Whether in public or private networks, 
the system authenticates the user identity through login passwords. Usually authentication 
is done by a username and password, although there are other various ways to be authenticated.

### Authorization
Authorization occurs after your identity is successfully authenticated by the system, 
which therefore gives you full access to resources such as information, files, databases, 
funds, etc. However authorization verifies your rights to grant you access to resources 
only after determining your ability to access the system and up to what extent. 
In other words, authorization is the process to determine whether the authenticated user 
has access to the particular resources

## Spring Boot and JWT
The diagram shows flow of how we implement User Registration, 
User Login and Authorization process.

![Spring Boot authentication JWT spring security flow](spring-boot-authentication-jwt-spring-security-flow.png)


### Add Spring Boot Security
We need to add following dependencies

```
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation group: 'io.jsonwebtoken', name: 'jjwt', version: '0.9.1'
```

### Change Swagger configuration
In order to configure the swagger to support authentication we need to change our SpringFoxConfig
```java
@Configuration
@EnableSwagger2
public class SpringFoxConfig {
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
            .select()
            .apis(RequestHandlerSelectors.any())
            .paths(PathSelectors.any())
            .build()
            .securityContexts(Collections.singletonList(securityContext()))
            .securitySchemes(Arrays.asList(idToken()))
            .pathMapping("/");
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder().securityReferences(defaultAuth()).forPaths(PathSelectors.regex("/.*")).build();
    }

    private ApiKey idToken() {
        return new ApiKey("Authorization", "Authorization", "header");
    }

    private List<SecurityReference> defaultAuth() {
        final AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        final AuthorizationScope[] authorizationScopes = new AuthorizationScope[]{authorizationScope};
        return Arrays.asList(new SecurityReference("Authorization", authorizationScopes));
    }
}
```

### Configure Spring Boot to connect to database
Under src/main/resources folder, open application.properties, add some new lines.
The url property provide information about database driver and connection URL.
Hibernate dialect gives information to translate JPQL to native SQL.
Ddl auto property describe what needed to be done when we connect to the database.
```
## Spring DATASOURCE (DataSourceAutoConfiguration & DataSourceProperties)
spring.datasource.url = jdbc:mysql://localhost:3306/internetProvider?createDatabaseIfNotExist=true
spring.datasource.username = root
spring.datasource.password =my-secret-pw
spring.batch.initialize-schema=always

## Hibernate Properties
# The SQL dialect makes Hibernate generate better SQL for the chosen database
spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.MySQL5InnoDBDialect

# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto = update
```

### Configure expiration time and secret
Under src/main/resources folder, open application.properties, add some new lines.
```
app.jwtSecret=internetprovider
app.jwtExpirationMs=3600000
```
### Database model for Users and Roles

#### User entity
Create User entity that implement  UserDetails.
The user entity contains username, password, email and set of roles(that current user have).
Also provide some more information about if user is active and block and etc.
```java
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Data
@Entity
@Table(name = "users")
public class User extends BaseEntity implements UserDetails {

    @Size(max = 20, min = 5)
    @NotBlank
    private String username;

    @NotBlank
    @Size(max = 80, min = 5)
    private String password;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```
#### Role entity
Create Role entity that implement GrantedAuthority.
```java
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "roles")
public class Role extends BaseEntity implements GrantedAuthority {

    @Enumerated(EnumType.STRING)
    private RoleType name;

    @Override
    public String getAuthority() {
        return name.name();
    }

    public enum RoleType{
        ROLE_CUSTOMER, ROLE_ADMIN, ROLE_MODERATOR
    }

}
```
### Repositories for User and Role entities
#### Role Repository
```java
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}
```
#### User Repository
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
```

### User Service 
User service implements UserDetailsService. 
It is used throughout the framework as a user DAO and is the strategy used by the DaoAuthenticationProvider. 
Spring Security will load User details to perform authentication & authorization.

```java
@RequiredArgsConstructor
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(String.format("User with username %s not found", username)));
    }
}
```
### JWT util class
JTW util class will provide us useful method for creating JWT token and validating.
Create new class called JwtUtils in  com.itdifferentcources.internetprovider.jwt.services.util package
```java
@Component
public class JwtUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {

        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        return Jwts.builder()
            .setSubject(userPrincipal.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            LOGGER.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            LOGGER.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            LOGGER.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}

```
### Handle AuthenticationException with JwtAuthenticationEntryPoint 
Now we create JwtAuthenticationEntryPoint class that implements AuthenticationEntryPoint interface. 
Then we override the commence() method. This method will be trigger anytime unauthenticated 
User requests a secured HTTP resource and an AuthenticationException is thrown.

Create this class in `com.itdifferentcources.internetprovider.jwt.configuration.jwt`

```java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```
### JWT Filter
Let’s define a filter that executes once per request. So we create AuthTokenFilter class 
that extends OncePerRequestFilter and override doFilterInternal() method.

Create this class in `com.itdifferentcources.internetprovider.jwt.configuration.jwt`
```java
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
                authentication
                    .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}

```

### Configure the entire security
```java
@RequiredArgsConstructor
@Configurable
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    private final JwtAuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public JwtAuthenticationTokenFilter authenticationJwtTokenFilter() {
        return new JwtAuthenticationTokenFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeRequests().antMatchers("/api/v1/auth/**").permitAll()
            .antMatchers("/api/**").authenticated()
            .antMatchers(HttpMethod.GET, "/**").permitAll();

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

```

### Start the application
So now you will be able only to access swagger UI. For all others endpoint you need to receive 401.

### Insert roles
Open your favorite database client, connect to database with the same credentials that you use in
application property file and insert following sql script:
```sql
INSERT INTO roles(name) VALUES('ROLE_CUSTOMER');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
```
Now you already have all roles that required for our application

## Signin and signup 

### DTOs for signin and sigup
We need to create SignupRequestDTO class with following fields,
username, password and email address.
```java
@RequiredArgsConstructor
@Data
public class SignupRequestDTO {

    @Size(max = 20, min = 5)
    @NotBlank
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 20, min = 5)
    private String password;
}
```
Then create a LoginRequestDTO class with following fields,
username and password.
```java
@RequiredArgsConstructor
@Data
public class LoginRequestDTO {
    private String username;
    private String password;
}
```
And at the end JwtResponseDTO that will return the token.
```java
@AllArgsConstructor
@Data
public class JwtResponseDTO {
    private String token;
}
```
### AuthenticationService
The service will provide functionality for signup and signin in our application.
Please take to account that the first user will have ADMIN role, then every user will have CUSTOMER role
```java
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;


    private static final Map<RoleType, Role>  roles = new HashMap<>();

    @PostConstruct
    protected void postConstruct(){
        roleRepository.findAll().stream()
            .forEach(role -> roles.put(role.getName(), role));
    }

    public void signup(SignupRequestDTO createUserDto) {
        Role role = roles.get(RoleType.ROLE_CUSTOMER);
        if(userRepository.count() == 0){
            role = roles.get(RoleType.ROLE_ADMIN);
        }
        if(userRepository.findByUsername(createUserDto.getUsername()).isPresent()){
         throw new RuntimeException(String.format("Username %s already exist", createUserDto.getUsername()));
        }
        User user = new User(createUserDto.getUsername(), passwordEncoder.encode(createUserDto.getPassword()), createUserDto.getEmail(),
            Set.of(role));
        userRepository.save(user);
    }

    public JwtResponseDTO signin(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        return new JwtResponseDTO(jwt);
    }
}

```

### AuthenticationController
Provide the API for signup and signin
```java
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody @Validated SignupRequestDTO createUserDto){
        authenticationService.signup(createUserDto);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public JwtResponseDTO signin(@RequestBody @Validated LoginRequestDTO loginRequestDTO){
        return authenticationService.signin(loginRequestDTO);
    }

}

```

### Lets create a test controller.
```java
@RequestMapping("/api/v1/test")
@RestController
public class TestController {

	@PreAuthorize("hasRole('CUSTOMER')")
    @GetMapping("/customer")
    public String testCustome(){
        return "HELLO CUSTOMER";
    }

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/admin")
	public String testAdmin(){
		return "HELLO ADMIN";
	}
}
```

## Let's try
1. Create two users
2. with the first user you will be able only to call `/api/v1/test/admin`.
The first user will have Admin ROLE.
3. with the second user you will be able only to call `/api/v1/test/customer`
The second user will have Customer ROLE