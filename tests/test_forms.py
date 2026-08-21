from dastng.orchestrator.forms import extract_forms


def test_extract_get_form_with_params():
    html = """
    <form action="/vulnerabilities/sqli/" method="GET">
      <input type="text" name="id" value="1">
      <input type="submit" name="Submit" value="Submit">
    </form>"""
    forms = extract_forms(html, "http://h/vulnerabilities/sqli/")
    assert len(forms) == 1
    f = forms[0]
    assert f.method == "GET"
    assert f.action == "http://h/vulnerabilities/sqli/"
    assert set(f.params) == {"id", "Submit"}
    assert f.csrf_field is None


def test_detects_csrf_token_field():
    html = """
    <form action="login.php" method="post">
      <input name="username"><input name="password" type="password">
      <input type="hidden" name="user_token" value="abc123">
      <input type="submit" name="Login" value="Login">
    </form>"""
    f = extract_forms(html, "http://h/login.php")[0]
    assert f.method == "POST"
    assert f.csrf_field == "user_token"
    # injectable params exclude the CSRF token
    assert "user_token" not in f.injectable_params()
    assert "username" in f.injectable_params()


def test_detects_generic_hidden_token():
    html = ('<form method=post action=/x>'
            '<input type=hidden name=authenticity_token value=z>'
            '<input name=q></form>')
    f = extract_forms(html, "http://h/x")[0]
    assert f.csrf_field == "authenticity_token"


def test_csrf_url_falls_back_to_source_page():
    html = '<form action="/submit" method="post"><input name="_csrf" type="hidden"></form>'
    f = extract_forms(html, "http://h/page")[0]
    assert f.csrf_url == "http://h/page"


def test_relative_action_resolved():
    f = extract_forms('<form action="do.php" method="get"><input name=a></form>',
                      "http://h/dir/page.php")[0]
    assert f.action == "http://h/dir/do.php"


def test_malformed_html_no_crash():
    assert extract_forms("<form><input name=x", "http://h/") != []  # unterminated form still captured
