package A3.projeto.A3Back.service;

import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service responsible for retrieving scam reports from the golpes_service microservice.
 * Handles HTTP communication, error scenarios, and data mapping.
 */
@Service
public class ScamRetrievalService {

    private static final Logger logger = LoggerFactory.getLogger(ScamRetrievalService.class);

    private final RestTemplate restTemplate;
    private final String scamServiceBaseUrl;
    private final EmpresaRepository empresaRepository;

    public ScamRetrievalService(
            RestTemplate restTemplate,
            @Value("${scam.service.base-url}") String scamServiceBaseUrl,
            EmpresaRepository empresaRepository) {
        this.restTemplate = restTemplate;
        this.scamServiceBaseUrl = scamServiceBaseUrl;
        this.empresaRepository = empresaRepository;
    }

    /**
     * Retrieves all scam reports for the logged-in user's company.
     * Looks up the company by username and retrieves associated scam reports.
     * Excludes CPF data for privacy.
     * 
     * @param username the username of the logged-in user
     * @return list of scam reports (GolpeDTO) without CPF data, or empty list if company not found or on failure
     */
    public List<GolpeDTO> getScamReportsByUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Username is null or empty, returning empty list");
            return Collections.emptyList();
        }

        logger.info("Retrieving scam reports for username: {}", username);

        // Find the company by username
        Optional<EmpresaModel> empresaOpt = empresaRepository.findByUsuario(username);
        
        if (empresaOpt.isEmpty()) {
            logger.warn("Company not found for username: {}", username);
            return Collections.emptyList();
        }

        EmpresaModel empresa = empresaOpt.get();
        logger.info("Found company with ID {} for username: {}", empresa.getId(), username);

        // Retrieve scam reports using the company ID
        return getScamReportsByCompanyId(empresa.getId());
    }

    /**
     * Retrieves all scam reports for a given company ID.
     * Excludes CPF data for privacy.
     * 
     * @param empresaId the ID of the company to search for
     * @return list of scam reports (GolpeDTO) without CPF data, or empty list on failure
     */
    public List<GolpeDTO> getScamReportsByCompanyId(Integer empresaId) {
        if (empresaId == null) {
            logger.warn("Company ID is null, returning empty list");
            return Collections.emptyList();
        }

        logger.info("Retrieving scam reports for company ID: {}", empresaId);

        try {
            String url = scamServiceBaseUrl + "/api/empresa/id/" + empresaId;
            
            ResponseEntity<List<GolpeResponse>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<List<GolpeResponse>>() {}
            );

            if (response.getBody() == null) {
                logger.info("No scam reports found for company ID: {}", empresaId);
                return Collections.emptyList();
            }

            List<GolpeDTO> scamReports = response.getBody().stream()
                    .map(this::mapToGolpeDTO)
                    .collect(Collectors.toList());

            logger.info("Successfully retrieved {} scam report(s) for company ID: {}", 
                    scamReports.size(), empresaId);
            
            return scamReports;

        } catch (org.springframework.web.client.ResourceAccessException e) {
            // Connection errors or timeouts
            logger.warn("Failed to connect to scam service for company ID {}: {}", 
                    empresaId, e.getMessage());
            return Collections.emptyList();
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            // HTTP 4xx errors (e.g., 404 Not Found)
            logger.warn("HTTP client error retrieving scam reports for company ID {}: {} - {}", 
                    empresaId, e.getStatusCode(), e.getMessage());
            return Collections.emptyList();
            
        } catch (org.springframework.web.client.HttpServerErrorException e) {
            // HTTP 5xx errors
            logger.warn("HTTP server error retrieving scam reports for company ID {}: {} - {}", 
                    empresaId, e.getStatusCode(), e.getMessage());
            return Collections.emptyList();
            
        } catch (Exception e) {
            // Any other unexpected exceptions
            logger.warn("Unexpected error retrieving scam reports for company ID {}: {} - {}", 
                    empresaId, e.getClass().getSimpleName(), e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Retrieves all scam reports for a given company name.
     * Performs case-insensitive matching and excludes CPF data for privacy.
     * 
     * @param companyName the name of the company to search for
     * @return list of scam reports (GolpeDTO) without CPF data, or empty list on failure
     * @deprecated Use getScamReportsByCompanyId instead for better data integrity
     */
    @Deprecated
    public List<GolpeDTO> getScamReportsByCompanyName(String companyName) {
        if (companyName == null || companyName.trim().isEmpty()) {
            logger.warn("Company name is null or empty, returning empty list");
            return Collections.emptyList();
        }

        logger.info("Retrieving scam reports for company: {}", companyName);

        try {
            String url = scamServiceBaseUrl + "/api/empresa/" + companyName;
            
            ResponseEntity<List<GolpeResponse>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<List<GolpeResponse>>() {}
            );

            if (response.getBody() == null) {
                logger.info("No scam reports found for company: {}", companyName);
                return Collections.emptyList();
            }

            List<GolpeDTO> scamReports = response.getBody().stream()
                    .map(this::mapToGolpeDTO)
                    .collect(Collectors.toList());

            logger.info("Successfully retrieved {} scam report(s) for company: {}", 
                    scamReports.size(), companyName);
            
            return scamReports;

        } catch (org.springframework.web.client.ResourceAccessException e) {
            // Connection errors or timeouts
            logger.warn("Failed to connect to scam service for company {}: {}", 
                    companyName, e.getMessage());
            return Collections.emptyList();
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            // HTTP 4xx errors (e.g., 404 Not Found)
            logger.warn("HTTP client error retrieving scam reports for company {}: {} - {}", 
                    companyName, e.getStatusCode(), e.getMessage());
            return Collections.emptyList();
            
        } catch (org.springframework.web.client.HttpServerErrorException e) {
            // HTTP 5xx errors
            logger.warn("HTTP server error retrieving scam reports for company {}: {} - {}", 
                    companyName, e.getStatusCode(), e.getMessage());
            return Collections.emptyList();
            
        } catch (Exception e) {
            // Any other unexpected exceptions
            logger.warn("Unexpected error retrieving scam reports for company {}: {} - {}", 
                    companyName, e.getClass().getSimpleName(), e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Maps GolpeResponse (from golpes_service) to GolpeDTO.
     * Explicitly excludes CPF field for privacy protection.
     * 
     * @param response the response from golpes_service
     * @return GolpeDTO without CPF data
     */
    private GolpeDTO mapToGolpeDTO(GolpeResponse response) {
        return new GolpeDTO(
                response.getId(),
                response.getNome(),
                response.getCidade(),
                response.getMeioDeContato(),
                response.getDescricao(),
                response.getEmailOuTelefone(),
                response.getEmpresa(),
                response.getCreatedAt()
        );
    }

    /**
     * Internal class to represent the response from golpes_service.
     * This includes the CPF field from the source, but it's not exposed in GolpeDTO.
     */
    private static class GolpeResponse {
        private Integer id;
        private String nome;
        private String cidade;
        private String cpf; // Received but not mapped to DTO
        private String meioDeContato;
        private String descricao;
        private String emailOuTelefone;
        private String empresa;
        private java.time.LocalDateTime createdAt;

        // Default constructor for Jackson deserialization
        public GolpeResponse() {
        }

        // Getters
        public Integer getId() {
            return id;
        }

        public String getNome() {
            return nome;
        }

        public String getCidade() {
            return cidade;
        }

        public String getCpf() {
            return cpf;
        }

        public String getMeioDeContato() {
            return meioDeContato;
        }

        public String getDescricao() {
            return descricao;
        }

        public String getEmailOuTelefone() {
            return emailOuTelefone;
        }

        public String getEmpresa() {
            return empresa;
        }

        public java.time.LocalDateTime getCreatedAt() {
            return createdAt;
        }

        // Setters
        public void setId(Integer id) {
            this.id = id;
        }

        public void setNome(String nome) {
            this.nome = nome;
        }

        public void setCidade(String cidade) {
            this.cidade = cidade;
        }

        public void setCpf(String cpf) {
            this.cpf = cpf;
        }

        public void setMeioDeContato(String meioDeContato) {
            this.meioDeContato = meioDeContato;
        }

        public void setDescricao(String descricao) {
            this.descricao = descricao;
        }

        public void setEmailOuTelefone(String emailOuTelefone) {
            this.emailOuTelefone = emailOuTelefone;
        }

        public void setEmpresa(String empresa) {
            this.empresa = empresa;
        }

        public void setCreatedAt(java.time.LocalDateTime createdAt) {
            this.createdAt = createdAt;
        }
    }
}
