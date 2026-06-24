@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // VULNERABLE: There is no @PreAuthorize("hasRole('ADMIN')") here.
    // The framework will route any authenticated request to this method.
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        userService.deleteAccount(id);
        return ResponseEntity.ok("User deleted.");
    }
}