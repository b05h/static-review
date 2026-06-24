@PostMapping(value = "/api/xml/upload", consumes = "application/xml")
public void parseXml(@RequestBody String xmlData) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // VULNERABLE: Missing the secure features to disable DTDs.
    // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); 
    
    DocumentBuilder builder = factory.newDocumentBuilder(); // Semgrep catches this missing configuration
    Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
}