package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.config.JwtUtil;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.service.ScamRetrievalService;
import net.jqwik.api.*;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assertions;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.*;

import static org.mockito.Mockito.*;

/**
 * Property-based tests for username extraction and usage in AuthController.
 * Feature: scam-search-by-username-at-login
 */
class AuthControllerUsernameExtractionPropertyTest {

    /**
     * Property 1: Username extraction and usage
     * Feature: scam-search-by-username-at-login, Property 1: Username extraction and usage
     * Validates: Requirements 1.1, 1.2
     * 
     * For any successful authentication, the company username from the authenticated EmpresaModel
     * should be used as the search parameter for scam retrieval.
     */
    @Property(tries = 100)
    void usernameFromAuthenticatedEmpresaShouldBeUsedForScamRetrieval(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyUsername
    ) {
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
        
        // Use a fixed password for testing
        String testPassword = "TestPassword123";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(testPassword);
        
        // Create a valid empresa model with the generated username
        EmpresaModel empresa = new EmpresaModel();
        empresa.setId(1);
        empresa.setUsuario(companyUsername.toUpperCase());
        empresa.setAtivo(true);
        empresa.setPasswordHash(encodedPassword);
        empresa.setCnpj("12345678901234");
        empresa.setRole(EmpresaModel.Role.EMPRESA);
        empresa.setCreatedAt(LocalDateTime.now());
        
        // Configure mocks
        when(mockRepository.findByUsuario(anyString())).thenReturn(Optional.of(empresa));
        when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn("mock-jwt-token");
        when(mockScamService.getScamReportsByCompanyName(anyString())).thenReturn(Collections.emptyList());
        
        // Execute: Call login
        AuthRequest request = new AuthRequest();
        request.setUsuario(companyUsername);
        request.setPassword(testPassword);
        
        ResponseEntity<?> response = controller.login(request);
        
        // Verify: Authentication succeeds
        Assertions.assertEquals(200, response.getStatusCodeValue(),
                "Authentication should succeed");
        
        // Verify: ScamRetrievalService was called with the empresa's username
        // The username should be extracted from the authenticated EmpresaModel
        verify(mockScamService, times(1))
                .getScamReportsByCompanyName(companyUsername.toUpperCase());
        
        // Verify: The username used for scam retrieval matches the empresa's username
        // This ensures we're using the username from the authenticated entity, not the request
        verify(mockScamService, times(1))
                .getScamReportsByCompanyName(empresa.getUsuario());
    }

    /**
     * Property 1 (variant): Username extraction with case variations
     * Verifies that the username from the authenticated empresa is used regardless of
     * the case of the input username in the login request.
     */
    @Property(tries = 100)
    void usernameExtractionShouldUseAuthenticatedEmpresaUsernameNotRequestUsername(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String baseUsername,
            @ForAll("caseVariation") String inputCase
    ) {
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
        
        // Use a fixed password for testing
        String testPassword = "TestPassword123";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(testPassword);
        
        // The empresa always stores username in uppercase
        String empresaUsername = baseUsername.toUpperCase();
        
        // Create a valid empresa model
        EmpresaModel empresa = new EmpresaModel();
        empresa.setId(1);
        empresa.setUsuario(empresaUsername);
        empresa.setAtivo(true);
        empresa.setPasswordHash(encodedPassword);
        empresa.setCnpj("12345678901234");
        empresa.setRole(EmpresaModel.Role.EMPRESA);
        empresa.setCreatedAt(LocalDateTime.now());
        
        // Apply case variation to the input username
        String inputUsername = applyCaseVariation(baseUsername, inputCase);
        
        // Configure mocks
        when(mockRepository.findByUsuario(anyString())).thenReturn(Optional.of(empresa));
        when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn("mock-jwt-token");
        when(mockScamService.getScamReportsByCompanyName(anyString())).thenReturn(Collections.emptyList());
        
        // Execute: Call login with the case-varied input
        AuthRequest request = new AuthRequest();
        request.setUsuario(inputUsername);
        request.setPassword(testPassword);
        
        ResponseEntity<?> response = controller.login(request);
        
        // Verify: Authentication succeeds
        Assertions.assertEquals(200, response.getStatusCodeValue(),
                "Authentication should succeed regardless of input case");
        
        // Verify: ScamRetrievalService was called with the empresa's username (uppercase)
        // NOT with the input username case variation
        verify(mockScamService, times(1))
                .getScamReportsByCompanyName(empresaUsername);
        
        // Verify: The service was NOT called with the input case variation
        // (unless it happens to be uppercase)
        if (!inputUsername.equals(empresaUsername)) {
            verify(mockScamService, never())
                    .getScamReportsByCompanyName(inputUsername);
        }
    }

    @Provide
    Arbitrary<String> caseVariation() {
        return Arbitraries.of("lowercase", "uppercase", "mixed");
    }

    private String applyCaseVariation(String input, String variation) {
        switch (variation) {
            case "lowercase":
                return input.toLowerCase();
            case "uppercase":
                return input.toUpperCase();
            case "mixed":
                return mixCase(input);
            default:
                return input;
        }
    }

    private String mixCase(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            result.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return result.toString();
    }
}
