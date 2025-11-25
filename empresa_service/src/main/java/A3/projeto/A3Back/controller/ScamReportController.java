package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.DTO.GolpeDTO;
import A3.projeto.A3Back.service.ScamRetrievalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for retrieving scam reports for the authenticated company.
 */
@RestController
@RequestMapping("/api/scam-reports")
public class ScamReportController {

    @Autowired
    private ScamRetrievalService scamRetrievalService;

    /**
     * Retrieves all scam reports for the logged-in user's company.
     * Uses the authenticated username to find the company and retrieve associated scam reports.
     * 
     * @return list of scam reports (GolpeDTO) without CPF data
     */
    @GetMapping("/my-company")
    public ResponseEntity<List<GolpeDTO>> getScamReportsForMyCompany() {
        // Get the authenticated username from Spring Security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        List<GolpeDTO> scamReports = scamRetrievalService.getScamReportsByUsername(username);
        
        return ResponseEntity.ok(scamReports);
    }

    /**
     * Alternative endpoint using @AuthenticationPrincipal for cleaner code.
     * Retrieves all scam reports for the logged-in user's company.
     * 
     * @param authentication the authenticated user principal
     * @return list of scam reports (GolpeDTO) without CPF data
     */
    @GetMapping("/me")
    public ResponseEntity<List<GolpeDTO>> getMyScamReports(Authentication authentication) {
        String username = authentication.getName();
        List<GolpeDTO> scamReports = scamRetrievalService.getScamReportsByUsername(username);
        
        return ResponseEntity.ok(scamReports);
    }
}
