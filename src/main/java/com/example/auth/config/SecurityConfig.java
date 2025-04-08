package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http.csrf(AbstractHttpConfigurer::disable);

        http.cors(cors ->
                cors.configurationSource(corsConfigurationSource())
        );

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());

        http.with(authorizationServerConfigurer, (authorizationServer) ->
                authorizationServer
                        .oidc(Customizer.withDefaults()));    // Enable OpenID Connect 1.0

        http.authorizeHttpRequests(authorize ->
                authorize.requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
        );

        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        http.exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.formLogin(Customizer.withDefaults());
        http.authorizeHttpRequests(
                c -> c.requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
        );

        return http.build();
    }

    // Настройка CORS
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:9090"));      // Разрешить запросы с порта 3000
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));  // Разрешить методы
        configuration.setAllowedHeaders(List.of("*"));                          // Разрешить любые заголовки
        configuration.setAllowCredentials(true);                                   // Разрешить отправку cookie

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);             // Применение ко всем маршрутам
        return source;
    }
}
