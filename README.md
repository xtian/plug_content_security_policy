# PlugContentSecurityPolicy

[![Build Status](https://secure.travis-ci.org/xtian/plug_content_security_policy.svg?branch=master
"Build Status")](https://travis-ci.org/xtian/plug_content_security_policy)

This is a [Plug][plug] module for inserting a [Content Security Policy][csp]
header into the response. It supports generating nonces for inline `<script>`
and `<style>` tags [as specified in CSP Level 2][nonces].

## Usage

Add `plug_content_security_policy` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:plug_content_security_policy, github: "xtian/plug_content_security_policy"}]
end
```

Add the `PlugContentSecurityPolicy` module to your pipeline:

```elixir
defmodule YourApp.Endpoint do
  # Use application config
  plug PlugContentSecurityPolicy

  # Pass configuration explicitly
  plug PlugContentSecurityPolicy,
    nonces_for: [:style_src]
    directives: %{script_src: ~w(https: 'self')}
end
```

If nonces are requested for any directives, they will be available in the
`assigns` map of the `conn` as `<directive>_nonce` — e.g.,
`conn.assigns[:style_src_nonce]` — and the nonce will be inserted into the
CSP header.

## Configuration

You can configure the CSP directives and using Mix. The default configuration
is shown below:

```elixir
config :plug_content_security_policy,
  nonces_for: nil
  directives: %{
    default_src: ~w('none'),
    connect_src: ~w('self'),
    child_src: ~w('self'),
    img_src: ~w('self'),
    script_src: ~w('self'),
    style_src: ~w('self')
  }
```

Values should be passed to each directive as a list of strings.
Please see the CSP spec for
[a full list of directives and valid attributes][directives].

To request that a nonce be generated for a directive, pass its key
to `nonces_for`:

```elixir
config :plug_content_security_policy,
  nonces_for: [:script_src]
```

[csp]: https://www.w3.org/TR/CSP2
[directives]: https://www.w3.org/TR/CSP2/#directives
[nonces]: https://www.w3.org/TR/CSP2/#script-src-nonce-usage
[plug]: https://github.com/elixir-lang/plug

## Licence

[ISC](LICENSE)
