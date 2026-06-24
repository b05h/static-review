@GetMapping("/api/invoices/{invoiceId}")
public Invoice getInvoice(@PathVariable String invoiceId, Authentication auth) {
    // 1. Fetches the invoice safely using an ORM
    Invoice invoice = invoiceRepository.findById(invoiceId);
    
    // VULNERABLE: It returns the invoice without verifying ownership.
    // Missing check: if (!invoice.getOwnerId().equals(auth.getName())) { throw Unauthorized(); }
    
    return invoice;
}