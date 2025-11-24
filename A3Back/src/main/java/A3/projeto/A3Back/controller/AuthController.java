package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.Security.JwtUtil;
import A3.projeto.A3Back.service.ScamRetrievalService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private EmpresaRepository empresaRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private ScamRetrievalService scamRetrievalService;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest req) {
        logger.info("Login attempt for user: {}", req.getUsuario());

        EmpresaModel emp = empresaRepository.findByUsuario(req.getUsuario().trim().toUpperCase())
                .orElse(null);

        if (emp == null) {
            logger.warn("User not found: {}", req.getUsuario());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }

        if (!emp.isAtivo()) {
            logger.warn("Inactive user attempted login: {}", emp.getUsuario());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }

        if (!encoder.matches(req.getPassword(), emp.getPasswordHash())) {
            logger.warn("Incorrect password for user: {}", emp.getUsuario());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }

        String token = jwtUtil.generateToken(emp.getUsuario(), Map.of("empresaId", emp.getId()));
        logger.info("JWT token generated successfully for user: {}", emp.getUsuario());

        // Retrieve scam reports for the company using company name (usuario)
        // This allows retrieval of scams registered before the company was created in the system
        List<GolpeDTO> scamReports = Collections.emptyList();
        try {
            scamReports = scamRetrievalService.getScamReportsByCompanyName(emp.getUsuario());
        } catch (Exception e) {
            // Handle any unexpected exceptions gracefully
            // Authentication should still succeed even if scam retrieval fails
            logger.error("Unexpected error retrieving scam reports for company {}: {}", 
                    emp.getUsuario(), e.getMessage(), e);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("empresa", emp.getUsuario());
        response.put("scamReports", scamReports);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String authHeader) {
        System.out.println(">>> [AuthController] Validando token: " + authHeader);

        String token = authHeader.replace("Bearer ", "");
        boolean valido = jwtUtil.validateToken(token);

        System.out.println(">>> [AuthController] Resultado da validação: " + valido);

        if (valido) {
            return ResponseEntity.ok("Token válido");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido");
        }
    }

}
