package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.Security.JwtUtil;
import A3.projeto.A3Back.model.EmpresaModel;
import A3.projeto.A3Back.service.ScamRetrievalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for AuthController scam integration.
 * Tests authentication flow with scam report retrieval.
 * Requirements: 1.2, 1.3, 1.4, 1.5, 2.3, 5.1, 5.2
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private EmpresaRepository empresaRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private ScamRetrievalService scamRetrievalService;

    @InjectMocks
    private AuthController authController;

    private BCryptPasswordEncoder encoder;
    private EmpresaModel testEmpresa;
    private AuthRequest authRequest;

    @BeforeEach
    void setUp() {
        encoder = new BCryptPasswordEncoder();
        
        // Create test empresa
        testEmpresa = new EmpresaModel();
        testEmpresa.setId(1);
        testEmpresa.setUsuario("TESTCOMPANY");
        testEmpresa.setCnpj("12345678901234");
        testEmpresa.setPasswordHash(encoder.encode("password123"));
        testEmpresa.setAtivo(true);
        testEmpresa.setRole(EmpresaModel.Role.EMPRESA);
        testEmpresa.setCreatedAt(LocalDateTime.now());

        // Create auth request
        authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");
    }

    /**
     * Test login with matching scam reports includes them in response.
     * Validates Requirements: 1.4, 4.1, 4.2, 4.3
     */
    @Test
    void testLoginWithMatchingScamReportsIncludesThemInResponse() {
        // Arrange
        List<GolpeDTO> scamReports = createTestScamReports(2);
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(scamReports);

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        
        assertEquals("test-jwt-token", responseBody.get("token"));
        assertEquals("TESTCOMPANY", responseBody.get("empresa"));
        
        @SuppressWarnings("unchecked")
        List<GolpeDTO> returnedScamReports = (List<GolpeDTO>) responseBody.get("scamReports");
        assertNotNull(returnedScamReports);
        assertEquals(2, returnedScamReports.size());
        
        // Verify service was called with username
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test login with no matching scam reports includes empty array.
     * Validates Requirements: 1.5, 4.1, 4.2, 4.3
     */
    @Test
    void testLoginWithNoMatchingScamReportsIncludesEmptyArray() {
        // Arrange
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(Collections.emptyList());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        
        assertEquals("test-jwt-token", responseBody.get("token"));
        assertEquals("TESTCOMPANY", responseBody.get("empresa"));
        
        @SuppressWarnings("unchecked")
        List<GolpeDTO> returnedScamReports = (List<GolpeDTO>) responseBody.get("scamReports");
        assertNotNull(returnedScamReports);
        assertTrue(returnedScamReports.isEmpty());
        
        // Verify service was called with username
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test login with scam service failure still succeeds with empty array.
     * Validates Requirements: 4.4, 6.4
     */
    @Test
    void testLoginWithScamServiceFailureStillSucceedsWithEmptyArray() {
        // Arrange
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenThrow(new RuntimeException("Service unavailable"));

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        
        assertEquals("test-jwt-token", responseBody.get("token"));
        assertEquals("TESTCOMPANY", responseBody.get("empresa"));
        
        @SuppressWarnings("unchecked")
        List<GolpeDTO> returnedScamReports = (List<GolpeDTO>) responseBody.get("scamReports");
        assertNotNull(returnedScamReports);
        assertTrue(returnedScamReports.isEmpty());
        
        // Verify service was called with username
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test response structure contains token, empresa, and scamReports fields.
     * Validates Requirements: 4.1, 4.2, 4.3
     */
    @Test
    void testResponseStructureContainsAllRequiredFields() {
        // Arrange
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        lenient().when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(Collections.emptyList());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        
        // Verify all three required fields are present
        assertTrue(responseBody.containsKey("token"));
        assertTrue(responseBody.containsKey("empresa"));
        assertTrue(responseBody.containsKey("scamReports"));
        
        // Verify field types
        assertInstanceOf(String.class, responseBody.get("token"));
        assertInstanceOf(String.class, responseBody.get("empresa"));
        assertInstanceOf(List.class, responseBody.get("scamReports"));
    }

    /**
     * Test case-insensitive company name matching.
     * Validates Requirements: 1.1, 1.2
     */
    @Test
    void testCaseInsensitiveCompanyNameMatching() {
        // Arrange - login with lowercase username
        authRequest.setUsuario("testcompany");
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(Collections.emptyList());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        // Verify that the service was called with the username
        verify(empresaRepository, times(1))
                .findByUsuario("TESTCOMPANY");
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test case-insensitive matching with mixed case input.
     * Validates Requirements: 1.1, 1.2
     */
    @Test
    void testCaseInsensitiveMatchingWithMixedCase() {
        // Arrange - login with mixed case username
        authRequest.setUsuario("TeStCoMpAnY");
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(Collections.emptyList());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        // Verify that the service was called with the username
        verify(empresaRepository, times(1))
                .findByUsuario("TESTCOMPANY");
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test login with whitespace in username is trimmed.
     * Validates Requirements: 1.1, 1.2
     */
    @Test
    void testLoginWithWhitespaceInUsernameIsTrimmed() {
        // Arrange - login with whitespace
        authRequest.setUsuario("  testcompany  ");
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(Collections.emptyList());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        // Verify that the service was called with the username
        verify(empresaRepository, times(1))
                .findByUsuario("TESTCOMPANY");
        verify(scamRetrievalService, times(1))
                .getScamReportsByCompanyName("TESTCOMPANY");
    }

    /**
     * Test login fails when user not found.
     */
    @Test
    void testLoginFailsWhenUserNotFound() {
        // Arrange
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.empty());

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Credenciais inválidas", response.getBody());
        
        // Verify scam service was never called
        verify(scamRetrievalService, never())
                .getScamReportsByCompanyId(anyInt());
    }

    /**
     * Test login fails when user is inactive.
     */
    @Test
    void testLoginFailsWhenUserIsInactive() {
        // Arrange
        testEmpresa.setAtivo(false);
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Credenciais inválidas", response.getBody());
        
        // Verify scam service was never called
        verify(scamRetrievalService, never())
                .getScamReportsByCompanyId(anyInt());
    }

    /**
     * Test login fails when password is incorrect.
     */
    @Test
    void testLoginFailsWhenPasswordIsIncorrect() {
        // Arrange
        authRequest.setPassword("wrongpassword");
        
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Credenciais inválidas", response.getBody());
        
        // Verify scam service was never called
        verify(scamRetrievalService, never())
                .getScamReportsByCompanyId(anyInt());
    }

    /**
     * Test backward compatibility - existing fields are maintained.
     * Validates Requirements: 4.1, 4.2
     */
    @Test
    void testBackwardCompatibilityExistingFieldsAreMaintained() {
        // Arrange
        when(empresaRepository.findByUsuario("TESTCOMPANY"))
                .thenReturn(Optional.of(testEmpresa));
        when(jwtUtil.generateToken(eq("TESTCOMPANY"), anyMap()))
                .thenReturn("test-jwt-token");
        lenient().when(scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY"))
                .thenReturn(createTestScamReports(1));

        // Act
        ResponseEntity<?> response = authController.login(authRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        
        // Verify existing fields are present and correct
        assertNotNull(responseBody.get("token"));
        assertNotNull(responseBody.get("empresa"));
        assertEquals("test-jwt-token", responseBody.get("token"));
        assertEquals("TESTCOMPANY", responseBody.get("empresa"));
    }

    /**
     * Helper method to create test scam reports.
     */
    private List<GolpeDTO> createTestScamReports(int count) {
        List<GolpeDTO> reports = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            GolpeDTO dto = new GolpeDTO();
            dto.setId(i);
            dto.setNome("Victim " + i);
            dto.setCidade("São Paulo");
            dto.setMeioDeContato("Email");
            dto.setDescricao("Scam description " + i);
            dto.setEmailOuTelefone("victim" + i + "@example.com");
            dto.setEmpresa("TESTCOMPANY");
            dto.setCreatedAt(LocalDateTime.now());
            reports.add(dto);
        }
        return reports;
    }
}
