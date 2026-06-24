@PostMapping("/api/network/ping")
public String pingHost(@RequestParam String targetIp) throws IOException {
    // VULNERABLE: An attacker could pass "127.0.0.1 && cat /etc/passwd"
    String command = "ping -c 3 " + targetIp;
    
    Process process = Runtime.getRuntime().exec(command); // Semgrep catches this sink
    return readProcessOutput(process);
}