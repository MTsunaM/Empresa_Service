package A3.projeto.A3Back.Security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
                // Filtro para logar todas as requisições
                .addFilterBefore((request, response, chain) -> {
                    HttpServletRequest httpReq = (HttpServletRequest) request;
                    System.out.println(">>> [Security] Requisição recebida: "
                            + httpReq.getMethod() + " " + httpReq.getRequestURI());
                    chain.doFilter(request, response);
                }, UsernamePasswordAuthenticationFilter.class)

                .csrf(csrf -> csrf.disable())
                .cors(cors -> {})
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Endpoints públicos
                        .requestMatchers("/error").permitAll()                   // Spring error endpoint
                        .requestMatchers("/api/auth/**").permitAll()            // login e validate
                        .requestMatchers("/api/cadastroempresas").permitAll()   // cadastro de empresas (exact match)
                        .requestMatchers("/api/cadastrogolpes").permitAll()     // cadastro de golpes (exact match)
                        // Qualquer outro endpoint exige token
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
