import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;

@Service
public class TwilioSmsProvider {

    @Value("${twilio.api.key}")
    private String injectedApiKey;

    private String activeApiKey;

    @PostConstruct
    public void init() {
        // VULNERABILITY: Hardcoded Secret Fallback (CWE-798)
        // The developer did the right thing by using @Value to inject the key from the environment.
        // But they got lazy during local testing, wrote a fallback, and accidentally committed it.
        if (injectedApiKey == null || injectedApiKey.isBlank()) {
            // Gitleaks will catch this entropy/pattern.
            this.activeApiKey = "SK2a8b9c7d6e5f4g3h2i1j0k9l8m7n6o5p"; 
        } else {
            this.activeApiKey = injectedApiKey;
        }
    }

    public void sendSms(String to, String message) {
        // Implementation using this.activeApiKey
    }
}