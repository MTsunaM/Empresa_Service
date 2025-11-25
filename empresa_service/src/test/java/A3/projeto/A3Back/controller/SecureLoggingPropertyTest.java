package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.config.JwtUtil;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.service.ScamRetrievalService;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import net.jqwik.api.*;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assertions;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Property-based tests for secure logging in authentication flow.
 * Feature: scam-search-by-username-at-login, Property 13: Secure logging
 * Validates: Requirements 5.5, 6.5
 */
class SecureLoggingPropertyTest {

    /**
     * Property 13: Secure logging
     * For any log output during scam operations, no password or CPF values should be present
     * in the log messages.
     * Feature: scam-search-by-username-at-login, Property 13: Secure logging
     * Validates: Requirements 5.5, 6.5
     */
    @Property(tries = 100)
    void logsShouldNotContainSensitiveAuthenticationData(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyUsername,
            @ForAll @StringLength(min = 8, max = 40) @AlphaChars String password
    ) {
        // Setup: Create a list appender to capture log messages
        Logger authControllerLogger = (Logger) LoggerFactory.getLogger(AuthController.class);
        Logger scamServiceLogger = (Logger) LoggerFactory.getLogger(ScamRetrievalService.class);
        
        ListAppender<ILoggingEvent> authListAppender = new ListAppender<>();
        ListAppender<ILoggingEvent> scamListAppender = new ListAppender<>();
        authListAppender.start();
        scamListAppender.start();
        
        authControllerLogger.addAppender(authListAppender);
        scamServiceLogger.addAppender(scamListAppender);
        
        try {
            // Setup: Create mocks
            AuthController controller = new AuthController();
            EmpresaRepository mockRepository = mock(EmpresaRepository.class);
            JwtUtil mockJwtUtil = mock(JwtUtil.class);
            ScamRetrievalService mockScamService = mock(ScamRetrievalService.class);
            
            // Use reflection to inject dependencies
            try {
                java.lang.reflect.Field repoField = AuthController.class.getDeclaredField("empresaRepository");
                repoField.setAccessible(true);
                repoField.set(controller, mockRepository);
                
                java.lang.reflect.Field jwtField = AuthController.class.getDeclaredField("jwtUtil");
                jwtField.setAccessible(true);
                jwtField.set(controller, mockJwtUtil);
                
                java.lang.reflect.Field scamField = AuthController.class.getDeclaredField("scamRetrievalService");
                scamField.setAccessible(true);
                scamField.set(controller, mockScamService);
            } catch (Exception e) {
                throw new RuntimeException("Failed to inject dependencies", e);
            }
            
            // Create password hash
            org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder = 
                    new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
            String passwordHash = encoder.encode(password);
            
            // Create a valid empresa model
            EmpresaModel empresa = new EmpresaModel();
            empresa.setId(1);
            empresa.setUsuario(companyUsername.toUpperCase());
            empresa.setAtivo(true);
            empresa.setPasswordHash(passwordHash);
            
            // Generate a JWT token
            String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            
            // Create mock scam reports with CPF data (to simulate what the service might process)
            GolpeDTO scamReport = new GolpeDTO();
            scamReport.setId(1);
            scamReport.setNome("Test Person");
            scamReport.setCidade("Test City");
            scamReport.setMeioDeContato("Email");
            scamReport.setDescricao("Test scam description");
            scamReport.setEmailOuTelefone("test@test.com");
            scamReport.setEmpresa(companyUsername.toUpperCase());
            scamReport.setCreatedAt(java.time.LocalDateTime.now());
            
            // Generate a CPF value that should NOT appear in logs
            String cpfValue = "123.456.789-00";
            
            // Configure mocks
            when(mockRepository.findByUsuario(anyString())).thenReturn(java.util.Optional.of(empresa));
            when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn(jwtToken);
            when(mockScamService.getScamReportsByCompanyName(anyString())).thenReturn(java.util.Arrays.asList(scamReport));
            
            // Execute: Call login
            AuthRequest request = new AuthRequest();
            request.setUsuario(companyUsername);
            request.setPassword(password);
            
            ResponseEntity<?> response = controller.login(request);
            
            // Verify: Authentication succeeds
            Assertions.assertEquals(200, response.getStatusCodeValue(),
                    "Authentication should succeed");
            
            // Collect all log messages
            List<ILoggingEvent> allLogEvents = new java.util.ArrayList<>();
            allLogEvents.addAll(authListAppender.list);
            allLogEvents.addAll(scamListAppender.list);
            
            // Verify: No log message contains the plain text password
            for (ILoggingEvent logEvent : allLogEvents) {
                String logMessage = logEvent.getFormattedMessage();
                
                Assertions.assertFalse(logMessage.contains(password),
                        "Log message should not contain plain text password: " + logMessage);
            }
            
            // Verify: No log message contains the password hash
            for (ILoggingEvent logEvent : allLogEvents) {
                String logMessage = logEvent.getFormattedMessage();
                
                Assertions.assertFalse(logMessage.contains(passwordHash),
                        "Log message should not contain password hash: " + logMessage);
            }
            
            // Verify: No log message contains the JWT token
            for (ILoggingEvent logEvent : allLogEvents) {
                String logMessage = logEvent.getFormattedMessage();
                
                Assertions.assertFalse(logMessage.contains(jwtToken),
                        "Log message should not contain JWT token: " + logMessage);
            }
            
            // Verify: No log message contains CPF values (Requirement 5.5)
            for (ILoggingEvent logEvent : allLogEvents) {
                String logMessage = logEvent.getFormattedMessage();
                
                // Check for explicit CPF value
                Assertions.assertFalse(logMessage.contains(cpfValue),
                        "Log message should not contain CPF value: " + logMessage);
                
                // Check for CPF-formatted patterns (XXX.XXX.XXX-XX)
                Assertions.assertFalse(logMessage.matches(".*\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}.*"),
                        "Log message should not contain CPF-formatted values: " + logMessage);
            }
            
            // Verify: Logs should contain the username (this is acceptable)
            boolean containsUsername = allLogEvents.stream()
                    .anyMatch(event -> event.getFormattedMessage().contains(companyUsername));
            
            Assertions.assertTrue(containsUsername,
                    "Logs should contain the username (non-sensitive information)");
            
        } finally {
            // Cleanup: Remove appenders
            authControllerLogger.detachAppender(authListAppender);
            scamServiceLogger.detachAppender(scamListAppender);
        }
    }
}
