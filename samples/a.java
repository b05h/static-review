import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public class UserRepositoryImpl implements CustomUserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // VULNERABILITY: HQL Injection (CWE-89 disguised in an ORM)
    // Semgrep must trace the 'companyDomain' parameter through the abstraction.
    @Override
    public List<User> findUsersByDynamicFilter(String companyDomain, String role) {
        // Real-world lazy dynamic query building
        String baseQuery = "SELECT u FROM User u WHERE u.role = '" + role + "'";
        
        if (companyDomain != null && !companyDomain.isEmpty()) {
            // Taint enters the query string here
            baseQuery += " AND u.email LIKE '%@" + companyDomain + "'";
        }

        // The Execution Sink (EntityManager instead of ResultSet)
        Query query = entityManager.createQuery(baseQuery);
        return query.getResultList();
    }
    
    // VULNERABILITY: Enterprise Cryptographic Failure (CWE-327)
    // Using ECB mode is deterministic. In a real app, this leaks patterns in encrypted PII.
    public byte[] encryptData(byte[] piiData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB is the flaw here
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(piiData);
    }
}