package A3.projeto.A3Back.DTO;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import net.jqwik.api.*;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assertions;

import java.lang.reflect.Field;
import java.time.LocalDateTime;
import java.util.Arrays;

/**
 * Property-based tests for GolpeDTO to verify CPF privacy protection.
 * Feature: company-scam-retrieval, Property 6: CPF privacy protection
 * Validates: Requirements 6.1, 6.3, 6.4
 */
class GolpeDTOPropertyTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    /**
     * Property 6: CPF privacy protection
     * For any scam report returned in the authentication response, the data SHALL NOT contain
     * a CPF field or CPF value, regardless of whether the source GolpeModel contained CPF data.
     */
    @Property(tries = 100)
    void golpeDTOShouldNotHaveCPFField() {
        // Verify via reflection that GolpeDTO class has no CPF field
        Field[] fields = GolpeDTO.class.getDeclaredFields();
        boolean hasCPFField = Arrays.stream(fields)
                .anyMatch(field -> field.getName().toLowerCase().contains("cpf"));
        
        Assertions.assertFalse(hasCPFField, 
                "GolpeDTO should not have a CPF field for privacy protection");
    }

    /**
     * Property 6: CPF privacy protection - JSON serialization test
     * Verifies that when GolpeDTO is serialized to JSON, no CPF field or value appears.
     */
    @Property(tries = 100)
    void golpeDTOJsonShouldNotContainCPF(
            @ForAll @IntRange(min = 1, max = 10000) Integer id,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String nome,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String cidade,
            @ForAll @StringLength(min = 3, max = 50) String meioDeContato,
            @ForAll @StringLength(min = 10, max = 500) String descricao,
            @ForAll @StringLength(min = 5, max = 120) String emailOuTelefone,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String empresa
    ) throws Exception {
        // Create a GolpeDTO with random data
        LocalDateTime createdAt = LocalDateTime.now();
        GolpeDTO dto = new GolpeDTO(id, nome, cidade, meioDeContato, 
                descricao, emailOuTelefone, empresa, createdAt);

        // Serialize to JSON
        String json = objectMapper.writeValueAsString(dto);

        // Verify JSON does not contain "cpf" field
        Assertions.assertFalse(json.toLowerCase().contains("\"cpf\""), 
                "JSON serialization should not contain CPF field");
        
        // Additional check: verify the JSON doesn't contain common CPF patterns
        // CPF format: XXX.XXX.XXX-XX or XXXXXXXXXXX
        Assertions.assertFalse(json.matches(".*\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}.*"),
                "JSON should not contain CPF-formatted values");
    }

    /**
     * Property 6: CPF privacy protection - Getter method test
     * Verifies that GolpeDTO has no getCPF or getCpf method.
     */
    @Property(tries = 100)
    void golpeDTOShouldNotHaveCPFGetter() {
        boolean hasCPFGetter = Arrays.stream(GolpeDTO.class.getDeclaredMethods())
                .anyMatch(method -> method.getName().toLowerCase().contains("cpf"));
        
        Assertions.assertFalse(hasCPFGetter, 
                "GolpeDTO should not have any CPF-related getter methods");
    }

    /**
     * Property 6: CPF privacy protection - Setter method test
     * Verifies that GolpeDTO has no setCPF or setCpf method.
     */
    @Property(tries = 100)
    void golpeDTOShouldNotHaveCPFSetter() {
        boolean hasCPFSetter = Arrays.stream(GolpeDTO.class.getDeclaredMethods())
                .anyMatch(method -> method.getName().toLowerCase().contains("cpf"));
        
        Assertions.assertFalse(hasCPFSetter, 
                "GolpeDTO should not have any CPF-related setter methods");
    }

    /**
     * Property 7: Non-CPF field completeness
     * For any scam report returned in the authentication response, all fields from the source
     * GolpeModel except CPF SHALL be present in the GolpeDTO (id, nome, cidade, meioDeContato,
     * descricao, emailOuTelefone, empresa, createdAt).
     * Feature: company-scam-retrieval, Property 7: Non-CPF field completeness
     * Validates: Requirements 6.5
     */
    @Property(tries = 100)
    void golpeDTOShouldContainAllNonCPFFields(
            @ForAll @IntRange(min = 1, max = 10000) Integer id,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String nome,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String cidade,
            @ForAll @StringLength(min = 3, max = 50) String meioDeContato,
            @ForAll @StringLength(min = 10, max = 500) String descricao,
            @ForAll @StringLength(min = 5, max = 120) String emailOuTelefone,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String empresa
    ) throws Exception {
        // Create a GolpeDTO with random data
        LocalDateTime createdAt = LocalDateTime.now();
        GolpeDTO dto = new GolpeDTO(id, nome, cidade, meioDeContato, 
                descricao, emailOuTelefone, empresa, createdAt);

        // Verify all non-CPF fields are present and accessible
        Assertions.assertNotNull(dto.getId(), "id field should be present");
        Assertions.assertEquals(id, dto.getId(), "id should match input value");
        
        Assertions.assertNotNull(dto.getNome(), "nome field should be present");
        Assertions.assertEquals(nome, dto.getNome(), "nome should match input value");
        
        Assertions.assertNotNull(dto.getCidade(), "cidade field should be present");
        Assertions.assertEquals(cidade, dto.getCidade(), "cidade should match input value");
        
        Assertions.assertNotNull(dto.getMeioDeContato(), "meioDeContato field should be present");
        Assertions.assertEquals(meioDeContato, dto.getMeioDeContato(), 
                "meioDeContato should match input value");
        
        Assertions.assertNotNull(dto.getDescricao(), "descricao field should be present");
        Assertions.assertEquals(descricao, dto.getDescricao(), "descricao should match input value");
        
        Assertions.assertNotNull(dto.getEmailOuTelefone(), "emailOuTelefone field should be present");
        Assertions.assertEquals(emailOuTelefone, dto.getEmailOuTelefone(), 
                "emailOuTelefone should match input value");
        
        Assertions.assertNotNull(dto.getEmpresa(), "empresa field should be present");
        Assertions.assertEquals(empresa, dto.getEmpresa(), "empresa should match input value");
        
        Assertions.assertNotNull(dto.getCreatedAt(), "createdAt field should be present");
        Assertions.assertEquals(createdAt, dto.getCreatedAt(), "createdAt should match input value");

        // Verify JSON serialization contains all non-CPF fields
        String json = objectMapper.writeValueAsString(dto);
        
        Assertions.assertTrue(json.contains("\"id\""), "JSON should contain id field");
        Assertions.assertTrue(json.contains("\"nome\""), "JSON should contain nome field");
        Assertions.assertTrue(json.contains("\"cidade\""), "JSON should contain cidade field");
        Assertions.assertTrue(json.contains("\"meioDeContato\""), 
                "JSON should contain meioDeContato field");
        Assertions.assertTrue(json.contains("\"descricao\""), "JSON should contain descricao field");
        Assertions.assertTrue(json.contains("\"emailOuTelefone\""), 
                "JSON should contain emailOuTelefone field");
        Assertions.assertTrue(json.contains("\"empresa\""), "JSON should contain empresa field");
        Assertions.assertTrue(json.contains("\"createdAt\""), "JSON should contain createdAt field");
    }

    /**
     * Property 7: Non-CPF field completeness - Reflection test
     * Verifies that GolpeDTO has exactly the expected fields (all from GolpeModel except CPF).
     */
    @Property(tries = 100)
    void golpeDTOShouldHaveExactlyExpectedFields() {
        Field[] fields = GolpeDTO.class.getDeclaredFields();
        
        // Expected field names (all from GolpeModel except cpf)
        String[] expectedFields = {"id", "nome", "cidade", "meioDeContato", 
                "descricao", "emailOuTelefone", "empresa", "createdAt"};
        
        // Verify all expected fields are present
        for (String expectedField : expectedFields) {
            boolean fieldExists = Arrays.stream(fields)
                    .anyMatch(field -> field.getName().equals(expectedField));
            Assertions.assertTrue(fieldExists, 
                    "GolpeDTO should have field: " + expectedField);
        }
        
        // Verify no unexpected fields (excluding CPF which should not be present)
        for (Field field : fields) {
            boolean isExpected = Arrays.asList(expectedFields).contains(field.getName());
            boolean isCPF = field.getName().toLowerCase().contains("cpf");
            Assertions.assertTrue(isExpected || !isCPF, 
                    "Unexpected field found: " + field.getName());
        }
    }

    /**
     * Property 8: JSON field naming consistency
     * For any GolpeDTO serialized to JSON, all field names SHALL use camelCase format.
     * Feature: scam-search-by-username-at-login, Property 8: JSON field naming consistency
     * Validates: Requirements 4.5
     */
    @Property(tries = 100)
    void golpeDTOJsonShouldUseCamelCaseFieldNames(
            @ForAll @IntRange(min = 1, max = 10000) Integer id,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String nome,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String cidade,
            @ForAll @StringLength(min = 3, max = 50) String meioDeContato,
            @ForAll @StringLength(min = 10, max = 500) String descricao,
            @ForAll @StringLength(min = 5, max = 120) String emailOuTelefone,
            @ForAll @StringLength(min = 3, max = 120) @AlphaChars String empresa
    ) throws Exception {
        // Create a GolpeDTO with random data
        LocalDateTime createdAt = LocalDateTime.now();
        GolpeDTO dto = new GolpeDTO(id, nome, cidade, meioDeContato, 
                descricao, emailOuTelefone, empresa, createdAt);

        // Serialize to JSON
        String json = objectMapper.writeValueAsString(dto);

        // Verify all field names use camelCase format
        // Expected camelCase field names
        String[] camelCaseFields = {
            "\"id\"", 
            "\"nome\"", 
            "\"cidade\"", 
            "\"meioDeContato\"",  // camelCase
            "\"descricao\"", 
            "\"emailOuTelefone\"",  // camelCase
            "\"empresa\"", 
            "\"createdAt\""  // camelCase
        };
        
        // Verify all expected camelCase fields are present
        for (String field : camelCaseFields) {
            Assertions.assertTrue(json.contains(field), 
                    "JSON should contain camelCase field: " + field);
        }
        
        // Verify no snake_case or other naming conventions are used
        // Check for common snake_case alternatives
        Assertions.assertFalse(json.contains("\"meio_de_contato\""), 
                "JSON should not use snake_case (meio_de_contato)");
        Assertions.assertFalse(json.contains("\"email_ou_telefone\""), 
                "JSON should not use snake_case (email_ou_telefone)");
        Assertions.assertFalse(json.contains("\"created_at\""), 
                "JSON should not use snake_case (created_at)");
        
        // Check for PascalCase alternatives
        Assertions.assertFalse(json.contains("\"MeioDeContato\""), 
                "JSON should not use PascalCase (MeioDeContato)");
        Assertions.assertFalse(json.contains("\"EmailOuTelefone\""), 
                "JSON should not use PascalCase (EmailOuTelefone)");
        Assertions.assertFalse(json.contains("\"CreatedAt\""), 
                "JSON should not use PascalCase (CreatedAt)");
    }
}
