import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/v2/billing")
public class BillingController {

    private final BillingService billingService;

    public BillingController(BillingService billingService) {
        this.billingService = billingService;
    }

    // VULNERABILITY: Blind DTO Trust (IDOR / CWE-639)
    // The endpoint has a generic @PreAuthorize("isAuthenticated()"), meaning ANY logged-in user can reach it.
    // However, it trusts the 'accountId' inside the DTO to apply the update.
    // User A can send a payload with User B's accountId, and the logic will blindly process it.
    @PutMapping("/payment-method")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> updatePaymentMethod(@RequestBody PaymentUpdateDTO payload) {
        
        // Tree-sitter isolates this logic block.
        // The AI will notice that the application does not verify if the currently 
        // authenticated SecurityContext user actually owns payload.getAccountId().
        boolean success = billingService.updateCreditCard(
            payload.getAccountId(), 
            payload.getStripeToken()
        );
        
        if (success) {
            return ResponseEntity.ok("Payment method updated.");
        }
        return ResponseEntity.badRequest().body("Update failed.");
    }
}