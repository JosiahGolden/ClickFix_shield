//Josiah Golden
//10/24/2025


fn main() {
    // Use rust-winres to embed icon + version info into the PE
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/icon.ico"); // file icon visible in Explorer
    // Optional metadata shown in file properties:
    res.set("FileDescription", "ClickFix Shield");
    res.set("ProductName", "ClickFix Shield");
    res.set("CompanyName", "Josiah Golden");
    res.set("LegalCopyright", "(c) 2025 Josiah Golden");
    res.set("OriginalFilename", "clickfix-shield.exe");
    res.compile().expect("Failed to embed resources");
}
