package com.auth0.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;

@Configuration
public class SecurityConfig {

    @Value("${security.oauth2.provider.issuer-uri}")
    private String issuer;
    @Value("${security.oauth2.client.registration.client-id}")
    private String clientId;
    @Value("${security.oauth2.client.registration.client-secret}")
    private String clientSecret;
    @Value("${security.oauth2.client.registration.token-uri}")
    private String tokenUri;
    @Value("${security.oauth2.client.registration.redirect-uri}")
    private String redirectUri;
    @Value("${security.oauth2.client.registration.jwt-set-uri}")
    private String jwtSetUri;
    @Value("${security.oauth2.client.registration.user-info}")
    private String userInfo;
    @Value("${security.oauth2.client.registration.logout}")
    private String logout;
    @Value("${security.oauth2.client.registration.client-name}")
    private String clientName;
    @Value("${security.oauth2.client.registration.attribute-name}")
    private String attributeName;
    @Value("${baseUrl}")
    private String baseUrl;
    @Value("${spring.profiles-active}")
    private String active;

    private LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            try {
                // Obtén el ID Token del usuario autenticado
                OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
                String idTokenHint = getIdTokenHint(oauth2AuthenticationToken);

                // Construye la URL de logout de Keycloak
                String logoutUrl = buildLogoutUrl(idTokenHint);

                // Redirige a Keycloak para hacer logout
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }

    private String getIdTokenHint(OAuth2AuthenticationToken authentication) {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        OidcIdToken idToken = oidcUser.getIdToken();
        return idToken.getTokenValue();  // Obtén el ID Token
    }

    private String buildLogoutUrl(String idTokenHint) {
        String logoutUrl = logout+"?client_id=" + clientId + "&returnTo=" + baseUrl;
        if (active.equals("keycloak")) {
             logoutUrl = logout
                    + "?post_logout_redirect_uri=" + baseUrl
                    + "&id_token_hint=" + idTokenHint;
        }
        return logoutUrl;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(authorizedClientService())
                )
                .logout(logout -> logout
                        .addLogoutHandler(logoutHandler())
                        .logoutSuccessUrl("http://localhost:3001")  // Redirige después de logout
                );

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(
                    ClientRegistration.withRegistrationId(clientName)
                            .clientId(clientId)
                            .clientSecret(clientSecret)
                            .scope("profile", "email", "openid")
                            .authorizationUri(issuer)
                            .tokenUri(tokenUri)
                            .userInfoUri(userInfo)
                            .redirectUri(baseUrl + redirectUri)
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .clientName(clientName)
                            .jwkSetUri(jwtSetUri)
                            .userNameAttributeName(attributeName)
                            .build()
            );
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }
}
