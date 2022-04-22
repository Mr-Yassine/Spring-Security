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
* Create Controller with /greeting Rest api
* Test /greeting GET Api without JWT

## Now will add spring security and JWT into our project.
* Project Structure

![image](https://user-images.githubusercontent.com/85122412/164738369-75c91f1b-23c1-4e28-a21a-60656edab8cf.png)
* Add Spring Security and JWT dependencies
* Provide secret key in propreties file. we provided the secret key used by the hashing algorithm . JWT combined this secret key with header and payload data. *"jwt.secret=techgeeknext"

## Spring Security and JWT Configuration
I will be performing 2 operation to configure spring security and to generate JWT and to validate it.
* Generate JWT : Use /authenticate POST endpoint by using username and password to generate a JSON Web Token (JWT).
* Validate JWT : User can use /greeting GET endpoint by using valid JSON Web Token (JWT).



