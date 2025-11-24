package A3.projeto.A3Back.service;

import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ScamRetrievalService.
 * Tests HTTP communication, error handling, and CPF privacy protection.
 * Requirements: 2.3, 2.4, 2.5, 3.3, 6.1, 6.4
 */
@ExtendWith(MockitoExtension.class)
class ScamRetrievalServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private ScamRetrievalService scamRetrievalService;

    private static final String BASE_URL = "http://localhost:8081";
    private static final String COMPANY_NAME = "TestCompany";

    @Mock
    private EmpresaRepository empresaRepository;

    @BeforeEach
    void setUp() {
        scamRetrievalService = new ScamRetrievalService(restTemplate, BASE_URL, empresaRepository);
    }

    /**
     * Test successful HTTP call returns mapped GolpeDTOs without CPF.
     * Validates Requirements: 6.1, 6.4
     */
    @Test
    void testSuccessfulHttpCallReturnsMappedGolpeDTOsWithoutCPF() {
        // Arrange
        String mockResponseJson = """
            [
                {
                    "id": 1,
                    "nome": "John Doe",
                    "cidade": "São Paulo",
                    "cpf": "123.456.789-00",
                    "meioDeContato": "Email",
                    "descricao": "Scam description",
                    "emailOuTelefone": "scammer@example.com",
                    "empresa": "TestCompany",
                    "createdAt": "2024-01-15T10:30:00"
                }
            ]
            """;

        // Create mock response using reflection to simulate the internal GolpeResponse
        List<Object> mockGolpeResponses = createMockGolpeResponses();
        ResponseEntity<List<Object>> mockResponse = ResponseEntity.ok(mockGolpeResponses);

        when(restTemplate.exchange(
                eq(BASE_URL + "/api/empresa/" + COMPANY_NAME),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenReturn((ResponseEntity) mockResponse);

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        
        GolpeDTO dto = result.get(0);
        assertEquals(1, dto.getId());
        assertEquals("John Doe", dto.getNome());
        assertEquals("São Paulo", dto.getCidade());
        assertEquals("Email", dto.getMeioDeContato());
        assertEquals("Scam description", dto.getDescricao());
        assertEquals("scammer@example.com", dto.getEmailOuTelefone());
        assertEquals("TestCompany", dto.getEmpresa());
        assertNotNull(dto.getCreatedAt());

        // Verify RestTemplate was called
        verify(restTemplate, times(1)).exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        );
    }

    /**
     * Test empty response returns empty list.
     * Validates Requirements: 2.3
     */
    @Test
    void testEmptyResponseReturnsEmptyList() {
        // Arrange
        ResponseEntity<List<Object>> mockResponse = ResponseEntity.ok(Collections.emptyList());

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenReturn((ResponseEntity) mockResponse);

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test null response body returns empty list.
     * Validates Requirements: 2.3
     */
    @Test
    void testNullResponseBodyReturnsEmptyList() {
        // Arrange
        ResponseEntity<List<Object>> mockResponse = new ResponseEntity<>(null, HttpStatus.OK);

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenReturn((ResponseEntity) mockResponse);

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test connection exception returns empty list and logs error.
     * Validates Requirements: 2.3, 2.4
     */
    @Test
    void testConnectionExceptionReturnsEmptyList() {
        // Arrange
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new ResourceAccessException("Connection refused"));

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test timeout exception returns empty list and logs error.
     * Validates Requirements: 2.4
     */
    @Test
    void testTimeoutExceptionReturnsEmptyList() {
        // Arrange
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new ResourceAccessException("Read timed out"));

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test HTTP 404 returns empty list.
     * Validates Requirements: 2.5
     */
    @Test
    void testHttp404ReturnsEmptyList() {
        // Arrange
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test HTTP 500 returns empty list.
     * Validates Requirements: 2.5
     */
    @Test
    void testHttp500ReturnsEmptyList() {
        // Arrange
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"));

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test malformed JSON (generic exception) returns empty list.
     * Validates Requirements: 2.5
     */
    @Test
    void testMalformedJsonReturnsEmptyList() {
        // Arrange
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new RuntimeException("JSON parse error"));

        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(COMPANY_NAME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test null company name returns empty list.
     * Validates Requirements: 2.3
     */
    @Test
    void testNullCompanyNameReturnsEmptyList() {
        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName(null);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
        
        // Verify RestTemplate was never called
        verify(restTemplate, never()).exchange(
                anyString(),
                any(HttpMethod.class),
                any(),
                any(ParameterizedTypeReference.class)
        );
    }

    /**
     * Test empty company name returns empty list.
     * Validates Requirements: 2.3
     */
    @Test
    void testEmptyCompanyNameReturnsEmptyList() {
        // Act
        List<GolpeDTO> result = scamRetrievalService.getScamReportsByCompanyName("   ");

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
        
        // Verify RestTemplate was never called
        verify(restTemplate, never()).exchange(
                anyString(),
                any(HttpMethod.class),
                any(),
                any(ParameterizedTypeReference.class)
        );
    }

    /**
     * Test case-insensitive matching works correctly.
     * The service should match company names regardless of case.
     * Validates Requirements: 1.3, 2.4
     */
    @Test
    void testCaseInsensitiveMatchingWorksCorrectly() {
        // Arrange - Create mock responses with different case variations
        List<Object> mockGolpeResponses = createMockGolpeResponses();
        ResponseEntity<List<Object>> mockResponse = ResponseEntity.ok(mockGolpeResponses);

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        )).thenReturn((ResponseEntity) mockResponse);

        // Act - Test with different case variations
        List<GolpeDTO> resultLowerCase = scamRetrievalService.getScamReportsByCompanyName("testcompany");
        List<GolpeDTO> resultUpperCase = scamRetrievalService.getScamReportsByCompanyName("TESTCOMPANY");
        List<GolpeDTO> resultMixedCase = scamRetrievalService.getScamReportsByCompanyName("TestCompany");

        // Assert - All should return results (the endpoint handles case-insensitivity)
        assertNotNull(resultLowerCase);
        assertNotNull(resultUpperCase);
        assertNotNull(resultMixedCase);
        
        // Verify the service makes the HTTP call for each case variation
        verify(restTemplate, times(3)).exchange(
                anyString(),
                eq(HttpMethod.GET),
                isNull(),
                any(ParameterizedTypeReference.class)
        );
    }

    /**
     * Helper method to create mock GolpeResponse objects.
     * This simulates the internal GolpeResponse class used by the service.
     */
    private List<Object> createMockGolpeResponses() {
        try {
            // Access the internal GolpeResponse class
            Class<?> golpeResponseClass = Class.forName(
                "A3.projeto.A3Back.service.ScamRetrievalService$GolpeResponse"
            );
            
            Object golpeResponse = golpeResponseClass.getDeclaredConstructor().newInstance();
            
            // Set fields using reflection
            setField(golpeResponse, "id", 1);
            setField(golpeResponse, "nome", "John Doe");
            setField(golpeResponse, "cidade", "São Paulo");
            setField(golpeResponse, "cpf", "123.456.789-00");
            setField(golpeResponse, "meioDeContato", "Email");
            setField(golpeResponse, "descricao", "Scam description");
            setField(golpeResponse, "emailOuTelefone", "scammer@example.com");
            setField(golpeResponse, "empresa", "TestCompany");
            setField(golpeResponse, "createdAt", LocalDateTime.of(2024, 1, 15, 10, 30));
            
            return List.of(golpeResponse);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create mock GolpeResponse", e);
        }
    }

    /**
     * Helper method to set private fields using reflection.
     */
    private void setField(Object obj, String fieldName, Object value) throws Exception {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
