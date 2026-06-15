import java.sql.Connection;
import java.sql.Statement;

public class Test {
    public void login(Connection conn, String username) throws Exception {
        Statement stmt = conn.createStatement();

        String query =
            "SELECT * FROM users WHERE name='" + username + "'";

        stmt.executeQuery(query);
    }
}