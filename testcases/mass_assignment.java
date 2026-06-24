@Entity
public class User {
    public Long id;
    public String username;
    public String password;
    public boolean isAdmin; // Attackers target this field
}

@RestController
public class ProfileController {

    @Autowired
    private UserRepository userRepository;

    // VULNERABLE: The framework maps {"isAdmin": true} from the request directly to the User object.
    @PostMapping("/api/profile/update")
    public void updateProfile(@RequestBody User user) {
        userRepository.save(user); 
    }
}