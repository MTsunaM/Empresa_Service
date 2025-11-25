package golpeservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        System.out.println(">>> [JwtAuthFilter] Processing request: " + request.getRequestURI());
        
        String authHeader = request.getHeader("Authorization");
        System.out.println(">>> [JwtAuthFilter] Authorization header: " + (authHeader != null ? "Present" : "Missing"));
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                System.out.println(">>> [JwtAuthFilter] Token extracted: " + token.substring(0, Math.min(20, token.length())) + "...");

                String username = jwtUtil.extractUsername(token);
                String role = jwtUtil.extractRole(token);
                
                System.out.println(">>> [JwtAuthFilter] Extracted username: " + username);
                System.out.println(">>> [JwtAuthFilter] Extracted role: " + role);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, null, jwtUtil.getAuthorities(role));
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    
                    System.out.println(">>> [JwtAuthFilter] Authentication set successfully");
                    System.out.println(">>> [JwtAuthFilter] Authorities: " + authToken.getAuthorities());
                }
            } catch (Exception e) {
                System.err.println(">>> [JwtAuthFilter] JWT Authentication Error: " + e.getMessage());
                e.printStackTrace();
                // Continue without authentication - let Spring Security handle authorization
            }
        }

        filterChain.doFilter(request, response);
    }
}