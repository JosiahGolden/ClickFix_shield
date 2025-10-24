fn main() {
    // Use rust-winres to embed icon + version info into the PE
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/icon.ico"); // file icon visible in Explorer
    // Optional metadata shown in file properties:
    res.set("FileDescription", "ClickFix Shield");
    res.set("ProductName", "ClickFix Shield");
    res.set("CompanyName", "Your Name or Org");
    res.set("LegalCopyright", "(c) 2025 Your Name");
    res.set("OriginalFilename", "clickfix-shield.exe");
    res.compile().expect("Failed to embed resources");
}
