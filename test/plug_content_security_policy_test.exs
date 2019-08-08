defmodule PlugContentSecurityPolicyTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias PlugContentSecurityPolicy, as: PlugCSP

  setup do
    {:ok, conn: conn(:get, "/")}
  end

  describe ".init/1" do
    test "pre-builds CSP directive if possible" do
      directives = %{
        default_src: ~w('none'),
        script_src: ~w('self' 'unsafe-inline')
      }

      pre_built = PlugCSP.init(directives: directives)

      assert pre_built ==
               {"content-security-policy",
                "default-src 'none'; script-src 'self' 'unsafe-inline';"}

      pre_built =
        PlugCSP.init(
          directives: %{report_uri: "/csp-violation-report-endpoint/"},
          report_only: true
        )

      assert pre_built ==
               {"content-security-policy-report-only",
                "report-uri /csp-violation-report-endpoint/;"}
    end

    test "merges defaults with provided config" do
      config = %{nonces_for: [:script_src]}
      new_config = PlugCSP.init(config)

      assert new_config.nonces_for == config.nonces_for
      assert new_config.directives
    end

    test "logs warnings for invalid config" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          PlugCSP.init(:foo)
        end)

      assert log =~ "[warn]"
    end
  end

  describe ".call/2" do
    test "sets the CSP header if pre-generated", %{conn: conn} do
      opts = PlugCSP.init(directives: %{default_src: ~w('none')})
      conn = PlugCSP.call(conn, opts)

      assert get_resp_header(conn, "content-security-policy") == ["default-src 'none';"]
      refute conn.assigns[:script_src_nonce]
      refute conn.assigns[:style_src_nonce]
    end

    test "generates nonces if required", %{conn: conn} do
      conn =
        PlugCSP.call(
          conn,
          %{
            directives: %{script_src: ~w('none')},
            nonces_for: [:script_src, :style_src],
            report_only: false
          }
        )

      [header] = get_resp_header(conn, "content-security-policy")

      assert header =~ "script-src 'nonce-#{conn.assigns.script_src_nonce}' 'none';"
      assert header =~ "style-src 'nonce-#{conn.assigns.style_src_nonce}';"
    end

    test "only assigns required nonce", %{conn: conn} do
      conn =
        PlugCSP.call(conn, %{
          directives: %{},
          nonces_for: [:style_src],
          report_only: false
        })

      refute conn.assigns[:script_src_nonce]
    end
  end
end
