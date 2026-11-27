# Load the public policy on the CLI before this primitive-only probe.
function check_name(label: string, header: string, want: string)
    {
    local got=PEFileDisguise::selected_filename(header);
    print fmt("%s %s expected_hex=%s actual_hex=%s",got==want ? "PASS" : "FAIL",label,bytestring_to_hexstr(want),bytestring_to_hexstr(got));
    }
event zeek_init()
    {
    check_name("extended-empty-fallback","attachment; filename=\"\"; filename*=UTF-8''report.pdf","report.pdf");
    check_name("extended-path-fallback","attachment; filename=\"../setup.exe\"; filename*=UTF-8''report.pdf","report.pdf");
    check_name("extended-colon-fallback","attachment; filename=\"C:setup.exe\"; filename*=UTF-8''photo.png","photo.png");
    check_name("extended-reverse-order","attachment; filename*=UTF-8''report.pdf; filename=\"\"","report.pdf");
    check_name("unsafe-selected-name","attachment; filename=\"report.pdf\"; filename*=UTF-8''..%2Fsetup.exe","");
    check_name("invalid-selected-language","attachment; filename=\"report.pdf\"; filename*=UTF-8'--'setup.exe","");
    check_name("duplicate-parameter","attachment; filename=\"x.exe\"; filename=\"report.pdf\"; filename*=UTF-8''photo.png","");
    check_name("malformed-fallback","attachment; filename=\"unterminated; filename*=UTF-8''report.pdf","");
    }
