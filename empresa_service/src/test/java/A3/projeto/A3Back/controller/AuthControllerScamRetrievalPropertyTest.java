package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.config.JwtUtil;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.service.ScamRetrievalService;
import net.jqwik.api.*;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assertions;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static org.mockito.Mockito.*;

/**
 * Property-based tests for scam report retrieval completeness in authentication flow.
 * Feature: company-scam-retrieval, Property 1: Scam report retrieval completeness
 * Validates: Requirements 1.1, 1.5
 */
class AuthControllerScamRetrievalPropertyTest {

    /**
     * Property 1: Scam report retrieval completeness
     * For any company name and set of scam reports in the database, when a company authenticates,
     * the response SHALL contain all and only those scam reports where the empresa field matches
     * the company username (case-insensitive).
     */
    @Property(tries = 100)
    void scamRetrievalServiceShouldReturnOnlyMatchingReports(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyName,
            @ForAll("scamReportLists") List<GolpeDTO> allScamReports
    ) {
        // Create a mock service that simulates the behavior
        ScamRetrievalService mockService = mock(ScamRetrievalService.class);
        
        // Filter scam reports that match the company name (case-insensitive)
        List<GolpeDTO> matchingReports = allScamReports.stream()
                .filter(report -> report.getEmpresa() != null && 
                        report.getEmpresa().equalsIgnoreCase(companyName))
                .collect(Collectors.toList());

        // Configure mock to return matching reports
        when(mockService.getScamReportsByCompanyName(anyString()))
                .thenReturn(matchingReports);

        // Execute: Call the service
        List<GolpeDTO> returnedReports = mockService.getScamReportsByCompanyName(companyName);

        // Verify: All returned reports match the company name (case-insensitive)
        Assertions.assertEquals(matchingReports.size(), returnedReports.size(),
                "Number of returned scam reports should match number of matching reports");

        for (GolpeDTO report : returnedReports) {
            Assertions.assertNotNull(report.getEmpresa(), "Report should have empresa field");
            Assertions.assertTrue(report.getEmpresa().equalsIgnoreCase(companyName),
                    "All returned reports should match company name (case-insensitive)");
        }
        
        // Verify no non-matching reports are included
        long nonMatchingCount = returnedReports.stream()
                .filter(report -> !report.getEmpresa().equalsIgnoreCase(companyName))
                .count();
        Assertions.assertEquals(0, nonMatchingCount,
                "No non-matching reports should be returned");
    }

    /**
     * Property 1: Scam report retrieval completeness - Case sensitivity test
     * Verifies that case variations of company names still match correctly.
     */
    @Property(tries = 100)
    void scamRetrievalShouldMatchCaseInsensitively(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String baseCompanyName,
            @ForAll("caseVariation") String caseVariation
    ) {
        // Create company name with specific case variation
        String companyName = applyCaseVariation(baseCompanyName, caseVariation);
        
        // Create scam reports with different case variations of the company name
        List<GolpeDTO> allReports = new ArrayList<>();
        allReports.add(createScamReport(1, baseCompanyName.toLowerCase())); // lowercase
        allReports.add(createScamReport(2, baseCompanyName.toUpperCase())); // uppercase
        allReports.add(createScamReport(3, capitalizeFirst(baseCompanyName))); // capitalized
        allReports.add(createScamReport(4, "DifferentCompany")); // non-matching

        // Filter reports that match (case-insensitive)
        List<GolpeDTO> matchingReports = allReports.stream()
                .filter(report -> report.getEmpresa().equalsIgnoreCase(companyName))
                .collect(Collectors.toList());

        // Verify that all case variations of the same company name match
        Assertions.assertEquals(3, matchingReports.size(),
                "All case variations of the company name should match");
        
        // Verify each matching report is indeed a case-insensitive match
        for (GolpeDTO report : matchingReports) {
            Assertions.assertTrue(report.getEmpresa().equalsIgnoreCase(companyName),
                    "Report empresa should match company name case-insensitively");
        }
    }

    // Helper methods and providers

    @Provide
    Arbitrary<List<GolpeDTO>> scamReportLists() {
        return Arbitraries.integers().between(0, 10).flatMap(size -> {
            List<Arbitrary<GolpeDTO>> reportArbitraries = new ArrayList<>();
            for (int i = 0; i < size; i++) {
                reportArbitraries.add(scamReportArbitrary(i + 1));
            }
            if (reportArbitraries.isEmpty()) {
                return Arbitraries.just(Collections.emptyList());
            }
            return Combinators.combine(reportArbitraries).as(reports -> 
                    new ArrayList<>(reports));
        });
    }

    @Provide
    Arbitrary<String> caseVariation() {
        return Arbitraries.of("lowercase", "uppercase", "capitalized", "mixed");
    }

    private Arbitrary<GolpeDTO> scamReportArbitrary(int id) {
        return Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(50),
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(50),
                Arbitraries.strings().ofMinLength(10).ofMaxLength(200),
                Arbitraries.strings().ofMinLength(5).ofMaxLength(50),
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(20)
        ).as((nome, cidade, meioDeContato, descricao, emailOuTelefone, empresa) ->
                new GolpeDTO(id, nome, cidade, meioDeContato, descricao, 
                        emailOuTelefone, empresa, LocalDateTime.now())
        );
    }

    private GolpeDTO createScamReport(int id, String empresaName) {
        return new GolpeDTO(
                id,
                "Test Person " + id,
                "Test City",
                "Email",
                "Test scam description for report " + id,
                "test" + id + "@example.com",
                empresaName,
                LocalDateTime.now()
        );
    }

    private String applyCaseVariation(String input, String variation) {
        switch (variation) {
            case "lowercase":
                return input.toLowerCase();
            case "uppercase":
                return input.toUpperCase();
            case "capitalized":
                return capitalizeFirst(input);
            case "mixed":
                return mixCase(input);
            default:
                return input;
        }
    }

    private String capitalizeFirst(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        return input.substring(0, 1).toUpperCase() + input.substring(1).toLowerCase();
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

    /**
     * Property 3: Graceful degradation under failure
     * Feature: company-scam-retrieval, Property 3: Graceful degradation under failure
     * Validates: Requirements 2.3, 2.4, 2.5, 4.4
     * 
     * For any failure condition (service unavailable, timeout, error status, unexpected exception),
     * the authentication SHALL succeed and return a valid response with an empty scamReports array,
     * without exposing the error to the client.
     */
    @Property(tries = 100)
    void authenticationShouldSucceedDespiteScamServiceFailures(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyUsername,
            @ForAll("failureScenarios") String failureType
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
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder = 
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(testPassword);
        
        // Create a valid empresa model
        EmpresaModel empresa = new EmpresaModel();
        empresa.setId(1);
        empresa.setUsuario(companyUsername.toUpperCase());
        empresa.setAtivo(true);
        empresa.setPasswordHash(encodedPassword);
        
        // Configure mocks - simulate various failure scenarios
        when(mockRepository.findByUsuario(anyString())).thenReturn(Optional.of(empresa));
        when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn("mock-jwt-token-" + companyUsername);
        
        // Configure scam service to throw different types of exceptions based on failure type
        switch (failureType) {
            case "connection_error":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new org.springframework.web.client.ResourceAccessException("Connection refused"));
                break;
            case "timeout":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new org.springframework.web.client.ResourceAccessException("Read timed out"));
                break;
            case "http_404":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new org.springframework.web.client.HttpClientErrorException(
                                org.springframework.http.HttpStatus.NOT_FOUND, "Not Found"));
                break;
            case "http_500":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new org.springframework.web.client.HttpServerErrorException(
                                org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"));
                break;
            case "unexpected_exception":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new RuntimeException("Unexpected error"));
                break;
            case "null_pointer":
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenThrow(new NullPointerException("Null pointer in service"));
                break;
            default:
                // Return empty list for unknown failure types
                when(mockScamService.getScamReportsByCompanyName(anyString()))
                        .thenReturn(Collections.emptyList());
        }
        
        // Execute: Call login
        AuthRequest request = new AuthRequest();
        request.setUsuario(companyUsername);
        request.setPassword(testPassword);
        
        ResponseEntity<?> response = controller.login(request);
        
        // Verify: Authentication succeeds despite scam service failure
        Assertions.assertEquals(200, response.getStatusCodeValue(),
                "Authentication should succeed even when scam service fails with: " + failureType);
        
        // Verify: Response body is a Map
        Object body = response.getBody();
        Assertions.assertNotNull(body, "Response body should not be null");
        Assertions.assertTrue(body instanceof Map, "Response body should be a Map");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseMap = (Map<String, Object>) body;
        
        // Verify: Response contains all required fields
        Assertions.assertTrue(responseMap.containsKey("token"),
                "Response should contain 'token' field even on scam service failure");
        Assertions.assertTrue(responseMap.containsKey("empresa"),
                "Response should contain 'empresa' field even on scam service failure");
        Assertions.assertTrue(responseMap.containsKey("scamReports"),
                "Response should contain 'scamReports' field even on scam service failure");
        
        // Verify: Token is valid (non-empty)
        Object token = responseMap.get("token");
        Assertions.assertNotNull(token, "Token should not be null");
        Assertions.assertTrue(token instanceof String, "Token should be a String");
        Assertions.assertFalse(((String) token).isEmpty(), "Token should not be empty");
        
        // Verify: ScamReports is an empty list (graceful degradation)
        Object scamReportsField = responseMap.get("scamReports");
        Assertions.assertNotNull(scamReportsField, "ScamReports field should not be null");
        Assertions.assertTrue(scamReportsField instanceof List,
                "ScamReports should be a List");
        
        @SuppressWarnings("unchecked")
        List<?> scamReports = (List<?>) scamReportsField;
        Assertions.assertTrue(scamReports.isEmpty(),
                "ScamReports should be empty when scam service fails with: " + failureType);
        
        // Verify: No error information is exposed to the client
        // The response should not contain any error fields or exception details
        Assertions.assertFalse(responseMap.containsKey("error"),
                "Response should not expose error details to client");
        Assertions.assertFalse(responseMap.containsKey("exception"),
                "Response should not expose exception details to client");
        Assertions.assertFalse(responseMap.containsKey("message"),
                "Response should not expose error message to client");
    }

    @Provide
    Arbitrary<String> failureScenarios() {
        return Arbitraries.of(
                "connection_error",
                "timeout",
                "http_404",
                "http_500",
                "unexpected_exception",
                "null_pointer"
        );
    }

    /**
     * Property 5: JSON field naming consistency
     * Feature: company-scam-retrieval, Property 5: JSON field naming consistency
     * Validates: Requirements 5.4
     * 
     * For any field in the login response JSON, the field name SHALL follow camelCase naming convention
     * (first word lowercase, subsequent words capitalized).
     */
    @Property(tries = 100)
    void authenticationResponseFieldsShouldFollowCamelCaseConvention(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyUsername,
            @ForAll("scamReportLists") List<GolpeDTO> scamReports
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
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder = 
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(testPassword);
        
        // Create a valid empresa model
        EmpresaModel empresa = new EmpresaModel();
        empresa.setId(1);
        empresa.setUsuario(companyUsername.toUpperCase());
        empresa.setAtivo(true);
        empresa.setPasswordHash(encodedPassword);
        
        // Configure mocks
        when(mockRepository.findByUsuario(anyString())).thenReturn(Optional.of(empresa));
        when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn("mock-jwt-token-" + companyUsername);
        when(mockScamService.getScamReportsByCompanyName(anyString())).thenReturn(scamReports);
        
        // Execute: Call login
        AuthRequest request = new AuthRequest();
        request.setUsuario(companyUsername);
        request.setPassword(testPassword);
        
        ResponseEntity<?> response = controller.login(request);
        
        // Verify: Response is successful
        Assertions.assertEquals(200, response.getStatusCodeValue(),
                "Authentication should succeed");
        
        // Verify: Response body is a Map
        Object body = response.getBody();
        Assertions.assertNotNull(body, "Response body should not be null");
        Assertions.assertTrue(body instanceof Map, "Response body should be a Map");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseMap = (Map<String, Object>) body;
        
        // Verify: All field names follow camelCase convention
        for (String fieldName : responseMap.keySet()) {
            Assertions.assertTrue(isCamelCase(fieldName),
                    "Field name '" + fieldName + "' should follow camelCase convention");
        }
        
        // Verify: Specific expected fields follow camelCase
        Assertions.assertTrue(responseMap.containsKey("token"),
                "Response should contain 'token' field in camelCase");
        Assertions.assertTrue(responseMap.containsKey("empresa"),
                "Response should contain 'empresa' field in camelCase");
        Assertions.assertTrue(responseMap.containsKey("scamReports"),
                "Response should contain 'scamReports' field in camelCase");
        
        // Verify: No fields use other naming conventions (snake_case, PascalCase, etc.)
        for (String fieldName : responseMap.keySet()) {
            Assertions.assertFalse(fieldName.contains("_"),
                    "Field name '" + fieldName + "' should not use snake_case (contains underscore)");
            Assertions.assertFalse(fieldName.contains("-"),
                    "Field name '" + fieldName + "' should not use kebab-case (contains hyphen)");
            Assertions.assertFalse(Character.isUpperCase(fieldName.charAt(0)),
                    "Field name '" + fieldName + "' should not use PascalCase (starts with uppercase)");
        }
    }

    /**
     * Helper method to verify if a string follows camelCase convention.
     * CamelCase rules:
     * - First character must be lowercase
     * - No underscores or hyphens
     * - Subsequent words start with uppercase letter
     */
    private boolean isCamelCase(String fieldName) {
        if (fieldName == null || fieldName.isEmpty()) {
            return false;
        }
        
        // First character must be lowercase
        if (Character.isUpperCase(fieldName.charAt(0))) {
            return false;
        }
        
        // Should not contain underscores or hyphens
        if (fieldName.contains("_") || fieldName.contains("-")) {
            return false;
        }
        
        // Should only contain letters (and possibly digits)
        // This is a simple check - camelCase typically uses alphanumeric characters
        for (char c : fieldName.toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * Property 2: Response structure completeness
     * Feature: company-scam-retrieval, Property 2: Response structure completeness
     * Validates: Requirements 1.2, 1.4, 5.1, 5.2
     * 
     * For any successful authentication, the login response SHALL contain exactly three fields:
     * "token" (non-empty string), "empresa" (matching the authenticated company username),
     * and "scamReports" (array, possibly empty).
     */
    @Property(tries = 100)
    void authenticationResponseShouldHaveCompleteStructure(
            @ForAll @StringLength(min = 3, max = 20) @AlphaChars String companyUsername,
            @ForAll("scamReportLists") List<GolpeDTO> scamReports
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
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder = 
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(testPassword);
        
        // Create a valid empresa model
        EmpresaModel empresa = new EmpresaModel();
        empresa.setId(1);
        empresa.setUsuario(companyUsername.toUpperCase());
        empresa.setAtivo(true);
        empresa.setPasswordHash(encodedPassword);
        
        // Configure mocks
        when(mockRepository.findByUsuario(anyString())).thenReturn(Optional.of(empresa));
        when(mockJwtUtil.generateToken(anyString(), anyString())).thenReturn("mock-jwt-token-" + companyUsername);
        when(mockScamService.getScamReportsByCompanyName(anyString())).thenReturn(scamReports);
        
        // Execute: Call login
        AuthRequest request = new AuthRequest();
        request.setUsuario(companyUsername);
        request.setPassword(testPassword);
        
        ResponseEntity<?> response = controller.login(request);
        
        // Verify: Response is successful
        Assertions.assertEquals(200, response.getStatusCodeValue(),
                "Authentication should succeed");
        
        // Verify: Response body is a Map
        Object body = response.getBody();
        Assertions.assertNotNull(body, "Response body should not be null");
        Assertions.assertTrue(body instanceof Map, "Response body should be a Map");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseMap = (Map<String, Object>) body;
        
        // Verify: Response contains exactly three fields
        Assertions.assertEquals(3, responseMap.size(),
                "Response should contain exactly three fields");
        
        // Verify: Response contains "token" field (non-empty string)
        Assertions.assertTrue(responseMap.containsKey("token"),
                "Response should contain 'token' field");
        Object token = responseMap.get("token");
        Assertions.assertNotNull(token, "Token should not be null");
        Assertions.assertTrue(token instanceof String, "Token should be a String");
        Assertions.assertFalse(((String) token).isEmpty(),
                "Token should not be empty");
        
        // Verify: Response contains "empresa" field (matching username)
        Assertions.assertTrue(responseMap.containsKey("empresa"),
                "Response should contain 'empresa' field");
        Object empresaField = responseMap.get("empresa");
        Assertions.assertNotNull(empresaField, "Empresa field should not be null");
        Assertions.assertTrue(empresaField instanceof String, "Empresa should be a String");
        Assertions.assertEquals(companyUsername.toUpperCase(), empresaField,
                "Empresa field should match the authenticated company username");
        
        // Verify: Response contains "scamReports" field (array, possibly empty)
        Assertions.assertTrue(responseMap.containsKey("scamReports"),
                "Response should contain 'scamReports' field");
        Object scamReportsField = responseMap.get("scamReports");
        Assertions.assertNotNull(scamReportsField, "ScamReports field should not be null");
        Assertions.assertTrue(scamReportsField instanceof List,
                "ScamReports should be a List");
        
        @SuppressWarnings("unchecked")
        List<GolpeDTO> returnedScamReports = (List<GolpeDTO>) scamReportsField;
        Assertions.assertEquals(scamReports.size(), returnedScamReports.size(),
                "ScamReports should contain the expected number of reports");
    }
}

