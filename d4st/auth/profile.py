"""Auth profile: the 'one-time set' login recipe.

A profile declares how to log in (form / token / interactive), the field selectors, the
success + validity markers, any post-login cookies (e.g. DVWA's `security` level), and TOTP
config. Profiles are YAML; a few are bundled (dvwa). The base URL is supplied at run time
(CLI --base or an env var) so one profile works across environments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib import resources


@dataclass
class AuthProfile:
    name: str
    type: str = "form"                       # form | token | interactive
    login_url: str = "{base}/login.php"
    username_selector: str = "input[name=username]"
    password_selector: str = "input[name=password]"
    submit_selector: str = "input[type=submit], button[type=submit]"
    username: str = ""
    password: str = ""
    username_env: str | None = None
    password_env: str | None = None
    success: dict = field(default_factory=dict)          # {url_contains, body_contains}
    validity: dict = field(default_factory=dict)         # {url, body_contains}
    post_login_cookies: list[dict] = field(default_factory=list)  # [{name, value, path}]
    totp: dict = field(default_factory=dict)             # {enabled, seed_env, selector}
    raw: dict = field(default_factory=dict)

    # ----- resolution --------------------------------------------------------

    def resolve_base(self, base: str | None) -> str:
        if base:
            return base.rstrip("/")
        env = self.raw.get("base_url_env")
        if env and os.environ.get(env):
            return os.environ[env].rstrip("/")
        raise ValueError(
            f"profile {self.name!r} needs a base URL (pass --base or set "
            f"{self.raw.get('base_url_env', 'the base URL')})"
        )

    def fmt(self, template: str, base: str) -> str:
        return template.replace("{base}", base)

    def creds(self) -> tuple[str, str]:
        user = os.environ.get(self.username_env) if self.username_env else None
        pw = os.environ.get(self.password_env) if self.password_env else None
        return (user or self.username, pw or self.password)

    def validity_url(self, base: str) -> str:
        url = self.validity.get("url") or self.success.get("url") or f"{base}/"
        return self.fmt(url, base)

    def validity_marker(self) -> str | None:
        return self.validity.get("body_contains") or self.success.get("body_contains")


def _from_dict(d: dict) -> AuthProfile:
    known = {
        "name", "type", "login_url", "username_selector", "password_selector",
        "submit_selector", "username", "password", "username_env", "password_env",
        "success", "validity", "post_login_cookies", "totp",
    }
    kwargs = {k: v for k, v in d.items() if k in known}
    kwargs["raw"] = d
    kwargs.setdefault("name", d.get("name", "profile"))
    return AuthProfile(**kwargs)


def load_profile(name_or_path: str) -> AuthProfile:
    import yaml
    if os.path.exists(name_or_path):
        with open(name_or_path, "r", encoding="utf-8") as fh:
            return _from_dict(yaml.safe_load(fh))
    fname = name_or_path if name_or_path.endswith(".yaml") else f"{name_or_path}.yaml"
    try:
        text = resources.files("d4st.auth.profiles").joinpath(fname).read_text(encoding="utf-8")
        return _from_dict(yaml.safe_load(text))
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        pass
    fs_path = os.path.join(os.path.dirname(__file__), "profiles", fname)
    if os.path.exists(fs_path):
        with open(fs_path, "r", encoding="utf-8") as fh:
            return _from_dict(yaml.safe_load(fh))
    raise FileNotFoundError(f"auth profile not found: {name_or_path!r}")
