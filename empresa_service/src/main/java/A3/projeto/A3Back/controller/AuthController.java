package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.AuthResponse;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.config.JwtUtil;
import A3.projeto.A3Back.service.ScamRetrievalService;

import java.util.Collections;
import java.util.List;

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

        if (emp == null || !emp.isAtivo() || !encoder.matches(req.getPassword(), emp.getPasswordHash())) {
            logger.warn("Invalid login attempt for user: {}", req.getUsuario());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }

        // Gera token com usuário e role
        String token = jwtUtil.generateToken(emp.getUsuario(), emp.getRole().name());
        logger.info("JWT token generated successfully for user: {}", emp.getUsuario());

        // Recupera golpes relacionados à empresa (se for EMPRESA)
        List<GolpeDTO> scamReports = Collections.emptyList();
        try {
            scamReports = scamRetrievalService.getScamReportsByCompanyName(emp.getUsuario());
        } catch (Exception e) {
            logger.error("Unexpected error retrieving scam reports for company {}: {}",
                    emp.getUsuario(), e.getMessage(), e);
        }

        AuthResponse response = new AuthResponse(token, emp.getUsuario(), emp.getRole().name());
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
