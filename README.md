# Spring-Security

The implementation of spring security for spring boot APIs

I will create a Spring Boot Application that uses JWT authentication to protect an exposed REST API. I will Configure JWT's Spring Security. Use the REST POST API to map /authenticate which user will receive a valid JSON Web Token. And then the user can only access the api / welcome if it has a valid token.

![image](https://user-images.githubusercontent.com/85122412/164737696-563e5984-ef36-45e8-b676-f0e423848805.png)

* Customers sign in by submitting their credentials to the provider.
* Upon successful authentication, it generates JWT containing user details and privileges for accessing the services and sets the JWT expiry date in payload.
* The server signs and encrypts the JWT if necessary and sends it to the client as a response with credentials to the initial request.
* Based on the expiration set by the server, the customer/client stores the JWT for a restricted or infinite amount of time.
* The client sends this JWT token in the header for all subsequent requests.
* The client authenticates the user with this token. So we don't need the client to send the user name and password to the server during each authentication process, but only once the server sends the client a JWT.

## First Steps :
* Create Simple Spring boot with /greeting rest end point from Spring Initializer site https://start.spring.io/
* Add dependecies
* Create Controller with /api/user Rest api
* Test /api/user GET Api without JWT

## Now will add spring security and JWT into our project.
* Project Structure

![image](https://user-images.githubusercontent.com/85122412/164738369-75c91f1b-23c1-4e28-a21a-60656edab8cf.png)
* Add Spring Security and JWT dependencies
* Provide secret key in propreties file. we provided the secret key used by the hashing algorithm . JWT combined this secret key with header and payload data. "jwt.secret=JwtKeyName"

## Spring Security and JWT Configuration
I will be performing 2 operation to configure spring security and to generate JWT and to validate it.
* Generate JWT : Use /authenticate POST endpoint by using username and password to generate a JSON Web Token (JWT).
* Validate JWT : User can use /api/user GET endpoint by using valid JSON Web Token (JWT).

## JWT Token Utility
I will define the utilities method for generating and validating JWT token.

```
@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -2550185165626007488L;
    public static final long JWT_TOKEN_VALIDITY = 5*60*60;

    @Value("${jwt.secret}")
    private String secret;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY*1000)).signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public Boolean canTokenBeRefreshed(String token) {
        return (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

# Load Username and Password
I used UserDetailsService interface from "org.springframework.security.core.userdetails.UserDetailsService" package provided by the spring security. UserDetailsService interface is used in order to search the username, password and GrantedAuthorities for given user.

This interface provide only one method called loadUserByUsername. Authentication Manager calls this method for getting the user details from the database when authenticating the user details provided by the user.

NOTE: In this code I will use hard coded username password. Use BCrypt password, you can use any online tool to BCrypt the password. 
```
@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("JwtKeyName".equals(username)) {
            return new User("JwtKeyName", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6",
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }
}
```

## Jwt Authentication Controller
I will use /authenticate POST API to authenticate username and password. Username and Password will passed in body and using Authentication Manager will authenticate the credentials. If credentials are valid, JWT token would be created by JWTTokenUtil and provided to client.
```
@RestController
@CrossOrigin
public class JwtAuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private UserDetailsService jwtInMemoryUserDetailsService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> generateAuthenticationToken(@RequestBody JwtRequest authenticationRequest)
			throws Exception {

		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

		final UserDetails userDetails = jwtInMemoryUserDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new JwtResponse(token));
	}

	private void authenticate(String username, String password) throws Exception {
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}
```

## Request Object
JwtRequest object used as a request object for getting username and password from the client.

```
public class JwtRequest implements Serializable {

	private static final long serialVersionUID = 5926468583005150707L;

	private String username;
	private String password;

	//default constructor for JSON Parsing
	public JwtRequest()
	{
	}

	public JwtRequest(String username, String password) {
		this.setUsername(username);
		this.setPassword(password);
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
```

## Response Object
JwtResponse used to create the response object send to the client.
```
public class JwtResponse implements Serializable {

	private static final long serialVersionUID = -8091879091924046844L;
	private final String jwttoken;

	public JwtResponse(String jwttoken) {
		this.jwttoken = jwttoken;
	}

	public String getToken() {
		return this.jwttoken;
	}
}
```

## JWT Request Filter
JwtRequestFilter class is executed for any incoming requests and validate JWT from the request and sets it in the context to indicate that logged in user is authenticated.
```
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUserDetailsService jwtUserDetailsService;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		final String requestTokenHeader = request.getHeader("Authorization");

		String username = null;
		String jwtToken = null;
		// JWT Token is in the form "Bearer token". Remove Bearer word and get only the Token
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			} catch (IllegalArgumentException e) {
				System.out.println("Unable to get JWT Token");
			} catch (ExpiredJwtException e) {
				System.out.println("JWT Token has expired");
			}
		} else {
			logger.warn("JWT Token does not begin with Bearer String");
		}

		//Once we get the token validate it.
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

			// if token is valid configure Spring Security to manually set authentication
			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the Spring Security Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		chain.doFilter(request, response);
	}

}
```

## JwtAuthenticationEntryPoint
This class rejects unauthenticated request and send error code 401
```
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

	private static final long serialVersionUID = -7858869558953243875L;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {

		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
	}
}
```

## WebSecurityConfig
This class extends the WebSecurityConfigurerAdapter that enables both WebSecurity and HTTPSecurity to be customized.
```
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	@Autowired
	private UserDetailsService jwtUserDetailsService;

	@Autowired
	private JwtRequestFilter jwtRequestFilter;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		// configure AuthenticationManager so that it knows from where to load
		// user for matching credentials
		// Use BCryptPasswordEncoder
		auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		// We don't need CSRF for this example
		httpSecurity.csrf().disable()
				// dont authenticate this particular request
				.authorizeRequests().antMatchers("/authenticate").permitAll().
				// all other requests need to be authenticated
				anyRequest().authenticated().and().
				// make sure we use stateless session; session won't be used to
				// store user's state.
				exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Add a filter to validate the tokens with every request
		httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}
}
```
## Testing
Now I will test this by using below steps:
* Generate JSON Web Token (JWT)
* Create POST request (localhost:8082/authenticate) and provide username and password in request body as given below.

![image](https://user-images.githubusercontent.com/85122412/164741634-e45d9b98-d51c-4504-a456-3e17a146ce16.png)

## Validate JSON Web Token (JWT)
Now use GET request localhost:8082/api/user with above generated JWT Token in header request.

![image](https://user-images.githubusercontent.com/85122412/164741890-ab0d3716-1dde-411f-99fa-6df064567b35.png)

