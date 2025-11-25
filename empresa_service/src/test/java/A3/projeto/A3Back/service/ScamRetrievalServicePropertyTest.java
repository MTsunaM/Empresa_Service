package A3.projeto.A3Back.service;

import A3.projeto.A3Back.DTO.GolpeDTO;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import net.jqwik.api.*;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assertions;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Property-based tests for ScamRetrievalService username-based search functionality.
 * Feature: scam-search-by-username-at-login
 */
class ScamRetrievalServicePropertyTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    /**
     * Property 2: Scam matching completeness
     * For any company username and set of scam reports, all scam reports where the empresa field
     * matches the username (case-insensitive) should be included in the results.
     * Feature: scam-search-by-username-at-login, Property 2: Scam matching completeness
     * Validates: Requirements 1.3, 2.2, 2.5
     */
    @Property(tries = 100)
    void allMatchingScamReportsShouldBeReturned(
            @ForAll @StringLength(min = 3, max = 50) @AlphaChars String companyName,
            @ForAll @IntRange(min = 0, max = 10) int matchingCount,
            @ForAll @IntRange(min = 0, max = 5) int nonMatchingCount
    ) throws Exception {
        // Create mock RestTemplate
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        String baseUrl = "http://localhost:8081";
        
        // Create ScamRetrievalService
        ScamRetrievalService service = new ScamRetrievalService(
                restTemplate, baseUrl, null);

        // Generate mock response with matching and non-matching scam reports using reflection
        List<Object> mockResponses = new ArrayList<>();
        
        // Add matching scam reports (empresa field matches companyName)
        for (int i = 0; i < matchingCount; i++) {
            Object response = createMockGolpeResponse(
                i + 1,
                "Person " + i,
                "City " + i,
                "123.456.789-0" + i,
                "Email",
                "Scam description " + i,
                "email" + i + "@test.com",
                companyName, // Exact match
                LocalDateTime.now()
            );
            mockResponses.add(response);
        }
        
        // Add non-matching scam reports (empresa field does NOT match)
        for (int i = 0; i < nonMatchingCount; i++) {
            Object response = createMockGolpeResponse(
                matchingCount + i + 1,
                "Other Person " + i,
                "Other City " + i,
                "987.654.321-0" + i,
                "Phone",
                "Other scam " + i,
                "other" + i + "@test.com",
                "DifferentCompany" + i, // Different company
                LocalDateTime.now()
            );
            mockResponses.add(response);
        }

        // Mock the RestTemplate response - simulate that the endpoint returns only matching reports
        List<Object> matchingResponses = mockResponses.stream()
                .filter(r -> {
                    try {
                        String empresa = (String) getField(r, "empresa");
                        return empresa.equalsIgnoreCase(companyName);
                    } catch (Exception e) {
                        return false;
                    }
                })
                .collect(Collectors.toList());
        
        ResponseEntity<List<Object>> responseEntity = ResponseEntity.ok(matchingResponses);

        Mockito.when(restTemplate.exchange(
                Mockito.eq(baseUrl + "/api/empresa/" + companyName),
                Mockito.eq(HttpMethod.GET),
                Mockito.isNull(),
                Mockito.<ParameterizedTypeReference<List<Object>>>any()
        )).thenReturn((ResponseEntity) responseEntity);

        // Call the service method
        List<GolpeDTO> result = service.getScamReportsByCompanyName(companyName);

        // Verify all matching scam reports are returned
        Assertions.assertEquals(matchingCount, result.size(),
                "Should return exactly " + matchingCount + " matching scam reports");
        
        // Verify all returned reports have the matching empresa field
        for (GolpeDTO dto : result) {
            Assertions.assertTrue(dto.getEmpresa().equalsIgnoreCase(companyName),
                    "All returned scam reports should have empresa matching " + companyName);
        }
    }

    /**
     * Helper method to create mock GolpeResponse objects using reflection.
     */
    private Object createMockGolpeResponse(Integer id, String nome, String cidade, String cpf,
                                           String meioDeContato, String descricao, 
                                           String emailOuTelefone, String empresa,
                                           LocalDateTime createdAt) throws Exception {
        Class<?> golpeResponseClass = Class.forName(
            "A3.projeto.A3Back.service.ScamRetrievalService$GolpeResponse"
        );
        
        Object golpeResponse = golpeResponseClass.getDeclaredConstructor().newInstance();
        
        setField(golpeResponse, "id", id);
        setField(golpeResponse, "nome", nome);
        setField(golpeResponse, "cidade", cidade);
        setField(golpeResponse, "cpf", cpf);
        setField(golpeResponse, "meioDeContato", meioDeContato);
        setField(golpeResponse, "descricao", descricao);
        setField(golpeResponse, "emailOuTelefone", emailOuTelefone);
        setField(golpeResponse, "empresa", empresa);
        setField(golpeResponse, "createdAt", createdAt);
        
        return golpeResponse;
    }

    /**
     * Helper method to set private fields using reflection.
     */
    private void setField(Object obj, String fieldName, Object value) throws Exception {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    /**
     * Helper method to get private fields using reflection.
     */
    private Object getField(Object obj, String fieldName) throws Exception {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    /**
     * Property 6: CPF exclusion
     * For any scam report retrieved from golpes_service, the CPF field should not be present
     * in the GolpeDTO or the JSON response.
     * Feature: scam-search-by-username-at-login, Property 6: CPF exclusion
     * Validates: Requirements 5.1, 5.3, 5.4
     */
    @Property(tries = 100)
    void cpfShouldBeExcludedFromGolpeDTO(
            @ForAll @StringLength(min = 3, max = 50) @AlphaChars String companyName,
            @ForAll @IntRange(min = 1, max = 10) int scamCount
    ) throws Exception {
        // Create mock RestTemplate
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        String baseUrl = "http://localhost:8081";
        
        // Create ScamRetrievalService
        ScamRetrievalService service = new ScamRetrievalService(
                restTemplate, baseUrl, null);

        // Generate mock response with CPF data (simulating golpes_service response)
        List<Object> mockResponses = new ArrayList<>();
        
        for (int i = 0; i < scamCount; i++) {
            // Create scam reports with CPF data
            String cpfValue = String.format("%03d.%03d.%03d-%02d", 
                    (i * 111) % 1000, 
                    (i * 222) % 1000, 
                    (i * 333) % 1000, 
                    (i * 11) % 100);
            
            Object response = createMockGolpeResponse(
                i + 1,
                "Person " + i,
                "City " + i,
                cpfValue, // CPF should be present in source data
                "Email",
                "Scam description " + i,
                "email" + i + "@test.com",
                companyName,
                LocalDateTime.now()
            );
            mockResponses.add(response);
        }

        // Mock the RestTemplate response
        ResponseEntity<List<Object>> responseEntity = ResponseEntity.ok(mockResponses);

        Mockito.when(restTemplate.exchange(
                Mockito.eq(baseUrl + "/api/empresa/" + companyName),
                Mockito.eq(HttpMethod.GET),
                Mockito.isNull(),
                Mockito.<ParameterizedTypeReference<List<Object>>>any()
        )).thenReturn((ResponseEntity) responseEntity);

        // Call the service method
        List<GolpeDTO> result = service.getScamReportsByCompanyName(companyName);

        // Verify CPF is excluded from all returned DTOs
        Assertions.assertEquals(scamCount, result.size(),
                "Should return " + scamCount + " scam reports");
        
        for (GolpeDTO dto : result) {
            // Verify DTO has no CPF field by checking all accessible fields
            Assertions.assertNotNull(dto.getId(), "id should be present");
            Assertions.assertNotNull(dto.getNome(), "nome should be present");
            Assertions.assertNotNull(dto.getCidade(), "cidade should be present");
            Assertions.assertNotNull(dto.getMeioDeContato(), "meioDeContato should be present");
            Assertions.assertNotNull(dto.getDescricao(), "descricao should be present");
            Assertions.assertNotNull(dto.getEmailOuTelefone(), "emailOuTelefone should be present");
            Assertions.assertNotNull(dto.getEmpresa(), "empresa should be present");
            Assertions.assertNotNull(dto.getCreatedAt(), "createdAt should be present");
            
            // Verify JSON serialization does not contain CPF
            String json = objectMapper.writeValueAsString(dto);
            Assertions.assertFalse(json.toLowerCase().contains("\"cpf\""),
                    "JSON should not contain CPF field");
            
            // Verify JSON doesn't contain CPF-formatted values
            Assertions.assertFalse(json.matches(".*\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}.*"),
                    "JSON should not contain CPF-formatted values");
        }
        
        // Additional verification: ensure GolpeDTO class has no CPF field
        java.lang.reflect.Field[] fields = GolpeDTO.class.getDeclaredFields();
        boolean hasCPFField = java.util.Arrays.stream(fields)
                .anyMatch(field -> field.getName().toLowerCase().contains("cpf"));
        
        Assertions.assertFalse(hasCPFField,
                "GolpeDTO class should not have a CPF field");
    }

    /**
     * Property 3: Case-insensitive matching
     * For any company username with mixed case characters, the search should match scam reports
     * regardless of the case of the empresa field.
     * Feature: scam-search-by-username-at-login, Property 3: Case-insensitive matching
     * Validates: Requirements 2.4
     */
    @Property(tries = 100)
    void caseInsensitiveMatchingShouldWork(
            @ForAll @StringLength(min = 3, max = 30) @AlphaChars String baseCompanyName,
            @ForAll @IntRange(min = 1, max = 5) int scamCount
    ) throws Exception {
        // Create mock RestTemplate
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        String baseUrl = "http://localhost:8081";
        
        // Create ScamRetrievalService
        ScamRetrievalService service = new ScamRetrievalService(
                restTemplate, baseUrl, null);

        // Generate different case variations of the company name
        String lowerCase = baseCompanyName.toLowerCase();
        String upperCase = baseCompanyName.toUpperCase();
        String mixedCase = baseCompanyName;
        
        // Create scam reports with different case variations
        List<Object> mockResponses = new ArrayList<>();
        for (int i = 0; i < scamCount; i++) {
            // Alternate between different case variations
            String empresaValue;
            if (i % 3 == 0) {
                empresaValue = lowerCase;
            } else if (i % 3 == 1) {
                empresaValue = upperCase;
            } else {
                empresaValue = mixedCase;
            }
            
            Object response = createMockGolpeResponse(
                i + 1,
                "Person " + i,
                "City " + i,
                "123.456.789-0" + i,
                "Email",
                "Scam description " + i,
                "email" + i + "@test.com",
                empresaValue, // Different case variation
                LocalDateTime.now()
            );
            mockResponses.add(response);
        }

        // Mock the RestTemplate response - the endpoint should return all matching reports
        // regardless of case
        ResponseEntity<List<Object>> responseEntity = ResponseEntity.ok(mockResponses);

        // Test with uppercase query
        Mockito.when(restTemplate.exchange(
                Mockito.eq(baseUrl + "/api/empresa/" + upperCase),
                Mockito.eq(HttpMethod.GET),
                Mockito.isNull(),
                Mockito.<ParameterizedTypeReference<List<Object>>>any()
        )).thenReturn((ResponseEntity) responseEntity);

        // Call the service method with uppercase
        List<GolpeDTO> resultUpper = service.getScamReportsByCompanyName(upperCase);

        // Verify all scam reports are returned (case-insensitive)
        Assertions.assertEquals(scamCount, resultUpper.size(),
                "Should return all " + scamCount + " scam reports regardless of case");
        
        // Verify all returned reports match the company name (case-insensitive)
        for (GolpeDTO dto : resultUpper) {
            Assertions.assertTrue(dto.getEmpresa().equalsIgnoreCase(baseCompanyName),
                    "Returned scam report empresa should match " + baseCompanyName + " (case-insensitive)");
        }

        // Test with lowercase query
        Mockito.when(restTemplate.exchange(
                Mockito.eq(baseUrl + "/api/empresa/" + lowerCase),
                Mockito.eq(HttpMethod.GET),
                Mockito.isNull(),
                Mockito.<ParameterizedTypeReference<List<Object>>>any()
        )).thenReturn((ResponseEntity) responseEntity);

        List<GolpeDTO> resultLower = service.getScamReportsByCompanyName(lowerCase);

        // Verify same results with lowercase query
        Assertions.assertEquals(scamCount, resultLower.size(),
                "Should return all " + scamCount + " scam reports with lowercase query");
        
        for (GolpeDTO dto : resultLower) {
            Assertions.assertTrue(dto.getEmpresa().equalsIgnoreCase(baseCompanyName),
                    "Returned scam report empresa should match " + baseCompanyName + " (case-insensitive)");
        }
    }

    /**
     * Property 9: Username logging
     * For any scam search operation, the company username should appear in the log output at INFO level.
     * Feature: scam-search-by-username-at-login, Property 9: Username logging
     * Validates: Requirements 6.1
     */
    @Property(tries = 100)
    void usernameLoggingShouldOccurAtInfoLevel(
            @ForAll @StringLength(min = 3, max = 50) @AlphaChars String companyName
    ) throws Exception {
        // Setup: Create a list appender to capture log messages
        Logger scamServiceLogger = (Logger) LoggerFactory.getLogger(ScamRetrievalService.class);
        
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        
        scamServiceLogger.addAppender(listAppender);
        
        try {
            // Create mock RestTemplate
            RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
            String baseUrl = "http://localhost:8081";
            
            // Create ScamRetrievalService
            ScamRetrievalService service = new ScamRetrievalService(
                    restTemplate, baseUrl, null);

            // Generate mock response with one scam report
            List<Object> mockResponses = new ArrayList<>();
            Object response = createMockGolpeResponse(
                1,
                "Test Person",
                "Test City",
                "123.456.789-00",
                "Email",
                "Test scam description",
                "test@test.com",
                companyName,
                LocalDateTime.now()
            );
            mockResponses.add(response);

            // Mock the RestTemplate response
            ResponseEntity<List<Object>> responseEntity = ResponseEntity.ok(mockResponses);

            Mockito.when(restTemplate.exchange(
                    Mockito.eq(baseUrl + "/api/empresa/" + companyName),
                    Mockito.eq(HttpMethod.GET),
                    Mockito.isNull(),
                    Mockito.<ParameterizedTypeReference<List<Object>>>any()
            )).thenReturn((ResponseEntity) responseEntity);

            // Call the service method
            service.getScamReportsByCompanyName(companyName);

            // Verify: The username appears in the log output
            List<ILoggingEvent> logEvents = listAppender.list;
            
            boolean usernameLoggedAtInfo = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("INFO") &&
                        event.getFormattedMessage().contains(companyName) &&
                        event.getFormattedMessage().contains("Retrieving scam reports for company")
                    );
            
            Assertions.assertTrue(usernameLoggedAtInfo,
                    "Username '" + companyName + "' should be logged at INFO level when retrieving scam reports");
            
            // Verify: The log message follows the expected format
            boolean correctLogFormat = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("INFO") &&
                        event.getFormattedMessage().matches(".*Retrieving scam reports for company: " + companyName + ".*")
                    );
            
            Assertions.assertTrue(correctLogFormat,
                    "Log message should follow the format 'Retrieving scam reports for company: {companyName}'");
            
        } finally {
            // Cleanup: Remove appender
            scamServiceLogger.detachAppender(listAppender);
        }
    }

    /**
     * Property 10: Success count logging
     * For any successful scam retrieval, the number of scam reports retrieved should appear
     * in the log output at INFO level.
     * Feature: scam-search-by-username-at-login, Property 10: Success count logging
     * Validates: Requirements 6.2
     */
    @Property(tries = 100)
    void successCountLoggingShouldOccurAtInfoLevel(
            @ForAll @StringLength(min = 3, max = 50) @AlphaChars String companyName,
            @ForAll @IntRange(min = 0, max = 10) int scamCount
    ) throws Exception {
        // Setup: Create a list appender to capture log messages
        Logger scamServiceLogger = (Logger) LoggerFactory.getLogger(ScamRetrievalService.class);
        
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        
        scamServiceLogger.addAppender(listAppender);
        
        try {
            // Create mock RestTemplate
            RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
            String baseUrl = "http://localhost:8081";
            
            // Create ScamRetrievalService
            ScamRetrievalService service = new ScamRetrievalService(
                    restTemplate, baseUrl, null);

            // Generate mock response with specified number of scam reports
            List<Object> mockResponses = new ArrayList<>();
            for (int i = 0; i < scamCount; i++) {
                Object response = createMockGolpeResponse(
                    i + 1,
                    "Person " + i,
                    "City " + i,
                    "123.456.789-0" + i,
                    "Email",
                    "Scam description " + i,
                    "email" + i + "@test.com",
                    companyName,
                    LocalDateTime.now()
                );
                mockResponses.add(response);
            }

            // Mock the RestTemplate response
            ResponseEntity<List<Object>> responseEntity = ResponseEntity.ok(mockResponses);

            Mockito.when(restTemplate.exchange(
                    Mockito.eq(baseUrl + "/api/empresa/" + companyName),
                    Mockito.eq(HttpMethod.GET),
                    Mockito.isNull(),
                    Mockito.<ParameterizedTypeReference<List<Object>>>any()
            )).thenReturn((ResponseEntity) responseEntity);

            // Call the service method
            List<GolpeDTO> result = service.getScamReportsByCompanyName(companyName);

            // Verify: The result has the expected count
            Assertions.assertEquals(scamCount, result.size(),
                    "Should return " + scamCount + " scam reports");

            // Verify: The success count appears in the log output
            List<ILoggingEvent> logEvents = listAppender.list;
            
            boolean successCountLogged = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("INFO") &&
                        event.getFormattedMessage().contains("Successfully retrieved") &&
                        event.getFormattedMessage().contains(String.valueOf(scamCount)) &&
                        event.getFormattedMessage().contains("scam report")
                    );
            
            Assertions.assertTrue(successCountLogged,
                    "Success count '" + scamCount + "' should be logged at INFO level after successful retrieval");
            
            // Verify: The log message follows the expected format
            String expectedPattern = ".*Successfully retrieved " + scamCount + " scam report.*for company: " + companyName + ".*";
            boolean correctLogFormat = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("INFO") &&
                        event.getFormattedMessage().matches(expectedPattern)
                    );
            
            Assertions.assertTrue(correctLogFormat,
                    "Log message should follow the format 'Successfully retrieved {count} scam report(s) for company: {companyName}'");
            
        } finally {
            // Cleanup: Remove appender
            scamServiceLogger.detachAppender(listAppender);
        }
    }

    /**
     * Property 11: Error logging
     * For any scam retrieval failure, the error details (exception type and message) should appear
     * in the log output at WARN level.
     * Feature: scam-search-by-username-at-login, Property 11: Error logging
     * Validates: Requirements 6.3
     */
    @Property(tries = 100)
    void errorLoggingShouldOccurAtWarnLevel(
            @ForAll @StringLength(min = 3, max = 50) @AlphaChars String companyName,
            @ForAll("errorScenarios") String errorType
    ) throws Exception {
        // Setup: Create a list appender to capture log messages
        Logger scamServiceLogger = (Logger) LoggerFactory.getLogger(ScamRetrievalService.class);
        
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        
        scamServiceLogger.addAppender(listAppender);
        
        try {
            // Create mock RestTemplate
            RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
            String baseUrl = "http://localhost:8081";
            
            // Create ScamRetrievalService
            ScamRetrievalService service = new ScamRetrievalService(
                    restTemplate, baseUrl, null);

            // Mock different error scenarios based on errorType
            Exception thrownException;
            String expectedExceptionType;
            String expectedErrorMessage;
            
            switch (errorType) {
                case "CONNECTION_ERROR":
                    expectedErrorMessage = "Connection refused";
                    thrownException = new ResourceAccessException(expectedErrorMessage);
                    expectedExceptionType = "ResourceAccessException";
                    break;
                    
                case "HTTP_404":
                    expectedErrorMessage = "Not Found";
                    thrownException = new HttpClientErrorException(HttpStatus.NOT_FOUND, expectedErrorMessage);
                    expectedExceptionType = "HttpClientErrorException";
                    break;
                    
                case "HTTP_500":
                    expectedErrorMessage = "Internal Server Error";
                    thrownException = new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, expectedErrorMessage);
                    expectedExceptionType = "HttpServerErrorException";
                    break;
                    
                case "UNEXPECTED":
                default:
                    expectedErrorMessage = "Unexpected error occurred";
                    thrownException = new RuntimeException(expectedErrorMessage);
                    expectedExceptionType = "RuntimeException";
                    break;
            }

            // Mock the RestTemplate to throw the exception
            Mockito.when(restTemplate.exchange(
                    Mockito.eq(baseUrl + "/api/empresa/" + companyName),
                    Mockito.eq(HttpMethod.GET),
                    Mockito.isNull(),
                    Mockito.<ParameterizedTypeReference<List<Object>>>any()
            )).thenThrow(thrownException);

            // Call the service method (should handle error gracefully)
            List<GolpeDTO> result = service.getScamReportsByCompanyName(companyName);

            // Verify: The result is an empty list (graceful degradation)
            Assertions.assertTrue(result.isEmpty(),
                    "Should return empty list on error");

            // Verify: Error details appear in the log output at WARN level
            List<ILoggingEvent> logEvents = listAppender.list;
            
            boolean errorLogged = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("WARN") &&
                        event.getFormattedMessage().contains(companyName)
                    );
            
            Assertions.assertTrue(errorLogged,
                    "Error should be logged at WARN level for company: " + companyName);
            
            // Verify: The log message contains the error message
            boolean errorMessageLogged = logEvents.stream()
                    .anyMatch(event -> 
                        event.getLevel().toString().equals("WARN") &&
                        event.getFormattedMessage().contains(expectedErrorMessage)
                    );
            
            Assertions.assertTrue(errorMessageLogged,
                    "Log message should contain the error message: " + expectedErrorMessage);
            
            // Verify: The log message contains information about the error type or context
            // The service logs different prefixes based on error type:
            // - "Failed to connect" for ResourceAccessException
            // - "HTTP client error" for HttpClientErrorException
            // - "HTTP server error" for HttpServerErrorException
            // - "Unexpected error" for other exceptions
            boolean errorContextLogged = logEvents.stream()
                    .anyMatch(event -> {
                        String message = event.getFormattedMessage();
                        return event.getLevel().toString().equals("WARN") &&
                               (message.contains("Failed to connect") ||
                                message.contains("HTTP client error") ||
                                message.contains("HTTP server error") ||
                                message.contains("Unexpected error") ||
                                message.contains("404") ||
                                message.contains("500"));
                    });
            
            Assertions.assertTrue(errorContextLogged,
                    "Log message should contain error context (connection failure, HTTP error, etc.)");
            
        } finally {
            // Cleanup: Remove appender
            scamServiceLogger.detachAppender(listAppender);
        }
    }

    /**
     * Provides different error scenarios for testing error logging.
     */
    @Provide
    Arbitrary<String> errorScenarios() {
        return Arbitraries.of("CONNECTION_ERROR", "HTTP_404", "HTTP_500", "UNEXPECTED");
    }
}
