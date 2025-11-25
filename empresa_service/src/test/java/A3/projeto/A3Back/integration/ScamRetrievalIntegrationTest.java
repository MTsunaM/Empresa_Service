package A3.projeto.A3Back.integration;

import A3.projeto.A3Back.DTO.AuthRequest;
import A3.projeto.A3Back.DTO.AuthResponse;
import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for end-to-end scam retrieval flow.
 * Tests complete authentication flow with HTTP calls to golpes_service.
 * Requirements: 1.1, 1.5, 3.4, 6.1, 6.3
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
    "scam.service.base-url=http://localhost:8081"
})
class ScamRetrievalIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private EmpresaRepository empresaRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private MockRestServiceServer mockServer;
    private BCryptPasswordEncoder encoder;
    private EmpresaModel testEmpresa;

    @BeforeEach
    void setUp() {
        // Initialize MockRestServiceServer to intercept HTTP calls
        mockServer = MockRestServiceServer.createServer(restTemplate);
        encoder = new BCryptPasswordEncoder();
        
        // Clean up and create test empresa
        empresaRepository.deleteAll();
        
        testEmpresa = new EmpresaModel();
        testEmpresa.setUsuario("TESTCOMPANY");
        testEmpresa.setCnpj("12345678901234");
        testEmpresa.setPasswordHash(encoder.encode("password123"));
        testEmpresa.setAtivo(true);
        testEmpresa.setRole(EmpresaModel.Role.EMPRESA);
        testEmpresa.setCreatedAt(LocalDateTime.now());
        testEmpresa = empresaRepository.save(testEmpresa);
    }

    /**
     * Test complete authentication flow with real HTTP call to golpes_service.
     * Validates Requirements: 1.3, 2.4, 2.5, 3.1
     */
    @Test
    void testCompleteAuthenticationFlowWithRealHttpCall() throws Exception {
        // Arrange - Mock golpes_service response
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "Scam description",
                    "emailOuTelefone": "scammer@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                }
            ]
            """;

        // Mock the username-based endpoint as per requirements
        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act - Perform login request
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        // Verify response structure
        assertTrue(response.containsKey("token"));
        assertTrue(response.containsKey("empresa"));
        assertTrue(response.containsKey("scamReports"));
        
        assertEquals("TESTCOMPANY", response.get("empresa"));
        assertNotNull(response.get("token"));
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertEquals(1, scamReports.size());
        
        Map<String, Object> scamReport = scamReports.get(0);
        assertEquals(1, scamReport.get("id"));
        assertEquals("John Doe", scamReport.get("nome"));
        assertEquals("São Paulo", scamReport.get("cidade"));
        assertEquals("Email", scamReport.get("meioDeContato"));
        assertEquals("Scam description", scamReport.get("descricao"));
        assertEquals("scammer@example.com", scamReport.get("emailOuTelefone"));
        assertEquals("TESTCOMPANY", scamReport.get("empresa"));
        
        // Verify MockRestServiceServer expectations
        mockServer.verify();
    }

    /**
     * Test multiple scam reports are all returned.
     * Validates Requirements: 2.5
     */
    @Test
    void testMultipleScamReportsAreAllReturned() throws Exception {
        // Arrange - Mock golpes_service response with multiple reports
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "First scam",
                    "emailOuTelefone": "scammer1@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                },
                {
                    "id": 2,
                    "nome": "Jane Smith",
                    "cidade": "Rio de Janeiro",
                    "cpf": "987.654.321-00",
                    "meioDeContato": "Telefone",
                    "descricao": "Second scam",
                    "emailOuTelefone": "555-1234",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-16T14:20:00"
                },
                {
                    "id": 3,
                    "nome": "Bob Johnson",
                    "cidade": "Brasília",
                    "cpf": "111.222.333-44",
                    "meioDeContato": "WhatsApp",
                    "descricao": "Third scam",
                    "emailOuTelefone": "555-5678",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-17T09:15:00"
                }
            ]
            """;

        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertEquals(3, scamReports.size());
        
        // Verify all three reports are present with correct data
        assertEquals("John Doe", scamReports.get(0).get("nome"));
        assertEquals("Jane Smith", scamReports.get(1).get("nome"));
        assertEquals("Bob Johnson", scamReports.get(2).get("nome"));
        
        assertEquals("First scam", scamReports.get(0).get("descricao"));
        assertEquals("Second scam", scamReports.get(1).get("descricao"));
        assertEquals("Third scam", scamReports.get(2).get("descricao"));
        
        mockServer.verify();
    }

    /**
     * Test case-insensitive matching works end-to-end.
     * Validates Requirements: 2.4
     */
    @Test
    void testCaseInsensitiveMatchingWorksEndToEnd() throws Exception {
        // Arrange - Mock golpes_service response
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "Scam description",
                    "emailOuTelefone": "scammer@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                }
            ]
            """;

        // Expect the service to call with uppercase username (normalized)
        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        // Test with lowercase username
        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertEquals(1, scamReports.size());
        
        mockServer.verify();
    }

    /**
     * Test case-insensitive matching with mixed case input.
     * Validates Requirements: 2.4
     */
    @Test
    void testCaseInsensitiveMatchingWithMixedCase() throws Exception {
        // Arrange
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "Scam description",
                    "emailOuTelefone": "scammer@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                }
            ]
            """;

        // Expect the service to call with uppercase username (normalized)
        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        // Test with mixed case username
        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("TeStCoMpAnY");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        assertEquals("TESTCOMPANY", response.get("empresa"));
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertEquals(1, scamReports.size());
        
        mockServer.verify();
    }

    /**
     * Test CPF field is excluded in actual HTTP response.
     * Validates Requirements: 5.1, 5.3
     */
    @Test
    void testCPFFieldIsExcludedInActualHttpResponse() throws Exception {
        // Arrange - Mock golpes_service response WITH CPF field
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "Scam description",
                    "emailOuTelefone": "scammer@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                }
            ]
            """;

        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        // Verify CPF is NOT in the JSON response
        assertFalse(responseBody.contains("cpf"), 
                "Response should not contain 'cpf' field");
        assertFalse(responseBody.contains("123.456.789-00"), 
                "Response should not contain CPF value");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertEquals(1, scamReports.size());
        
        Map<String, Object> scamReport = scamReports.get(0);
        
        // Verify CPF field is not present in the scam report
        assertFalse(scamReport.containsKey("cpf"), 
                "Scam report should not contain 'cpf' field");
        
        // Verify all other fields ARE present
        assertTrue(scamReport.containsKey("id"));
        assertTrue(scamReport.containsKey("nome"));
        assertTrue(scamReport.containsKey("cidade"));
        assertTrue(scamReport.containsKey("meioDeContato"));
        assertTrue(scamReport.containsKey("descricao"));
        assertTrue(scamReport.containsKey("emailOuTelefone"));
        assertTrue(scamReport.containsKey("empresa"));
        assertTrue(scamReport.containsKey("createdAt"));
        
        mockServer.verify();
    }

    /**
     * Test CPF privacy with multiple scam reports.
     * Validates Requirements: 5.1, 5.3
     */
    @Test
    void testCPFPrivacyWithMultipleScamReports() throws Exception {
        // Arrange - Multiple reports with different CPF values
        String mockGolpesResponse = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "First scam",
                    "emailOuTelefone": "scammer1@example.com",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-15T10:30:00"
                },
                {
                    "id": 2,
                    "nome": "Jane Smith",
                    "cidade": "Rio de Janeiro",
                    "cpf": "987.654.321-00",
                    "meioDeContato": "Telefone",
                    "descricao": "Second scam",
                    "emailOuTelefone": "555-1234",
                    "empresa": "TESTCOMPANY",
                    "createdAt": "2024-01-16T14:20:00"
                }
            ]
            """;

        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        // Verify NO CPF values are in the response
        assertFalse(responseBody.contains("cpf"));
        assertFalse(responseBody.contains("123.456.789-00"));
        assertFalse(responseBody.contains("987.654.321-00"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertEquals(2, scamReports.size());
        
        // Verify neither report contains CPF
        for (Map<String, Object> report : scamReports) {
            assertFalse(report.containsKey("cpf"));
        }
        
        mockServer.verify();
    }

    /**
     * Test empty scam reports when no matches found.
     * Validates Requirements: 1.3
     */
    @Test
    void testEmptyScamReportsWhenNoMatchesFound() throws Exception {
        // Arrange - Empty response from golpes_service
        String mockGolpesResponse = "[]";

        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(mockGolpesResponse, MediaType.APPLICATION_JSON));

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertTrue(scamReports.isEmpty());
        
        mockServer.verify();
    }

    /**
     * Test scam service unavailable scenario.
     * Validates Requirements: 3.3
     */
    @Test
    void testScamServiceUnavailableScenario() throws Exception {
        // Arrange - Mock service unavailable (connection error)
        mockServer.expect(requestTo("http://localhost:8081/api/empresa/TESTCOMPANY"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(request -> {
                    throw new org.springframework.web.client.ResourceAccessException("Connection refused");
                });

        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsuario("testcompany");
        authRequest.setPassword("password123");

        // Act
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // Assert - Authentication should still succeed with empty scam reports
        String responseBody = result.getResponse().getContentAsString();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        // Verify response structure is intact
        assertTrue(response.containsKey("token"));
        assertTrue(response.containsKey("empresa"));
        assertTrue(response.containsKey("scamReports"));
        
        assertEquals("TESTCOMPANY", response.get("empresa"));
        assertNotNull(response.get("token"));
        
        // Verify scam reports is empty due to service failure
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scamReports = (List<Map<String, Object>>) response.get("scamReports");
        assertNotNull(scamReports);
        assertTrue(scamReports.isEmpty(), "Scam reports should be empty when service is unavailable");
        
        mockServer.verify();
    }
}
